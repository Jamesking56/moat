use crate::support::github::{Client, Fetch};
use crate::support::outcome::CheckOutcome;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use std::collections::BTreeMap;

const COLLABORATOR_CONCURRENCY: usize = 12;

pub struct OrgContext {
    pub two_factor_required: TwoFactorState,
    pub members_without_2fa: MemberList,
    pub outside_collaborators: MemberList,
    pub admins: MemberList,
    pub default_repository_permission: DefaultRepoPermissionState,
    pub release_immutability: ReleaseImmutabilityState,
}

#[derive(Clone, Copy)]
pub enum TwoFactorState {
    Required,
    NotRequired,
    Unknown,
}

#[derive(Clone, Copy)]
pub enum ReleaseImmutabilityState {
    Enabled,
    Disabled,
    Unknown,
}

pub enum MemberList {
    Ok(Vec<String>),
    NoPermission,
}

pub enum DefaultRepoPermissionState {
    None,
    Read,
    Write,
    Admin,
    Other(String),
    Unknown,
}

impl MemberList {
    pub fn outcome(
        &self,
        empty: CheckOutcome,
        found: impl FnOnce(&[String]) -> CheckOutcome,
    ) -> CheckOutcome {
        match self {
            MemberList::NoPermission => CheckOutcome::skipped("(requires org admin token)"),
            MemberList::Ok(v) if v.is_empty() => empty,
            MemberList::Ok(v) => found(v).with_items(v.clone()),
        }
    }
}

#[derive(Deserialize)]
struct OrgResponse {
    two_factor_requirement_enabled: Option<bool>,
    default_repository_permission: Option<String>,
    immutable_releases: Option<bool>,
}

#[derive(Deserialize)]
struct User {
    login: String,
}

impl OrgContext {
    pub async fn fetch(client: &Client, org: &str) -> Result<Self> {
        let (two_factor_required, default_repository_permission, release_immutability) =
            match client
                .get_json::<OrgResponse>(&format!("/orgs/{org}"))
                .await?
            {
                Fetch::Ok(o) => {
                    let tfa = match o.two_factor_requirement_enabled {
                        Some(true) => TwoFactorState::Required,
                        Some(false) => TwoFactorState::NotRequired,
                        None => TwoFactorState::Unknown,
                    };
                    let perm = match o.default_repository_permission.as_deref() {
                        Some("none") => DefaultRepoPermissionState::None,
                        Some("read") => DefaultRepoPermissionState::Read,
                        Some("write") => DefaultRepoPermissionState::Write,
                        Some("admin") => DefaultRepoPermissionState::Admin,
                        Some(other) => DefaultRepoPermissionState::Other(other.to_string()),
                        None => DefaultRepoPermissionState::Unknown,
                    };
                    let immutability = match o.immutable_releases {
                        Some(true) => ReleaseImmutabilityState::Enabled,
                        Some(false) => ReleaseImmutabilityState::Disabled,
                        None => ReleaseImmutabilityState::Unknown,
                    };
                    (tfa, perm, immutability)
                }
                _ => (
                    TwoFactorState::Unknown,
                    DefaultRepoPermissionState::Unknown,
                    ReleaseImmutabilityState::Unknown,
                ),
            };

        let members_without_2fa =
            fetch_logins(client, &format!("/orgs/{org}/members?filter=2fa_disabled")).await?;
        let outside_collaborators = fetch_outside_collaborators(client, org).await?;
        let admins = fetch_logins(client, &format!("/orgs/{org}/members?role=admin")).await?;

        Ok(Self {
            two_factor_required,
            members_without_2fa,
            outside_collaborators,
            admins,
            default_repository_permission,
            release_immutability,
        })
    }
}

async fn fetch_logins(client: &Client, path: &str) -> Result<MemberList> {
    match client.get_paginated::<User>(path).await? {
        Fetch::Ok(users) => Ok(MemberList::Ok(users.into_iter().map(|u| u.login).collect())),
        Fetch::Forbidden => Ok(MemberList::NoPermission),
        Fetch::NotFound => Ok(MemberList::Ok(Vec::new())),
    }
}

#[derive(Deserialize)]
struct RepoBrief {
    name: String,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    fork: bool,
    #[serde(default)]
    archived: bool,
}

#[derive(Deserialize)]
struct CollaboratorEntry {
    login: String,
    #[serde(default)]
    permissions: CollaboratorPerms,
}

#[derive(Deserialize, Default)]
struct CollaboratorPerms {
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    maintain: bool,
    #[serde(default)]
    push: bool,
    #[serde(default)]
    triage: bool,
}

impl CollaboratorPerms {
    fn is_more_than_read(&self) -> bool {
        self.admin || self.maintain || self.push || self.triage
    }
}

async fn fetch_outside_collaborators(client: &Client, org: &str) -> Result<MemberList> {
    let all = fetch_logins(client, &format!("/orgs/{org}/outside_collaborators")).await?;
    let logins = match all {
        MemberList::Ok(v) if !v.is_empty() => v,
        other => return Ok(other),
    };

    let repos: Vec<RepoBrief> = match client
        .get_paginated::<RepoBrief>(&format!("/orgs/{org}/repos?type=all"))
        .await?
    {
        Fetch::Ok(v) => v.into_iter().filter(|r| !r.fork && !r.archived).collect(),
        Fetch::Forbidden | Fetch::NotFound => return Ok(MemberList::Ok(logins)),
    };

    let pairs: Vec<(String, String)> = stream::iter(repos)
        .map(|repo| async move {
            let path = format!(
                "/repos/{org}/{}/collaborators?affiliation=outside",
                repo.name
            );
            let collaborators = match client.get_paginated::<CollaboratorEntry>(&path).await {
                Ok(Fetch::Ok(v)) => v,
                _ => return Vec::new(),
            };
            collaborators
                .into_iter()
                .filter(|c| repo.private || c.permissions.is_more_than_read())
                .map(|c| (c.login, repo.name.clone()))
                .collect::<Vec<_>>()
        })
        .buffer_unordered(COLLABORATOR_CONCURRENCY)
        .flat_map(stream::iter)
        .collect()
        .await;

    let mut by_login: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (login, repo) in pairs {
        by_login.entry(login).or_default().push(repo);
    }
    for repos in by_login.values_mut() {
        repos.sort();
        repos.dedup();
    }

    Ok(MemberList::Ok(
        logins
            .into_iter()
            .filter_map(|l| {
                by_login
                    .get(&l)
                    .map(|repos| format!("{l} ({})", repos.join(", ")))
            })
            .collect(),
    ))
}
