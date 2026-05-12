use crate::support::github::{Client, Fetch};
use crate::support::outcome::CheckOutcome;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use owo_colors::OwoColorize;
use serde::Deserialize;
use std::collections::BTreeMap;

fn step(label: &str) {
    eprintln!("  {} {}", "→".bright_black(), label.dimmed());
}

const COLLABORATOR_CONCURRENCY: usize = 12;

pub struct OrgContext {
    pub two_factor_required: TwoFactorState,
    pub members_without_2fa: MemberList,
    pub outside_collaborators: MemberList,
    pub admins: MemberList,
    pub default_repository_permission: DefaultRepoPermissionState,
    pub release_immutability: ReleaseImmutabilityState,
    pub fork_pr_contributor_approval: ForkPrContributorApprovalState,
    pub workflow_token: WorkflowTokenState,
    pub secret_scanning_default: FeatureDefaultState,
    pub push_protection_default: FeatureDefaultState,
    pub dependabot_alerts_default: FeatureDefaultState,
}

#[derive(Clone, Copy)]
pub enum WorkflowTokenState {
    Read,
    Write,
    Unknown,
}

#[derive(Clone, Copy)]
pub enum FeatureDefaultState {
    Enabled,
    Disabled,
    NotSet,
    Unknown,
}

#[derive(Clone, Copy)]
pub enum ForkPrContributorApprovalState {
    AllExternalContributors,
    FirstTimeContributors,
    FirstTimeContributorsNewToGithub,
    Other,
    Unknown,
}

#[derive(Clone, Copy)]
pub enum TwoFactorState {
    Required,
    NotRequired,
    Unknown,
}

#[derive(Clone, Copy)]
pub enum ReleaseImmutabilityState {
    All,
    Selected,
    None,
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
}

#[derive(Deserialize)]
struct ImmutableReleasesResponse {
    enforced_repositories: Option<String>,
}

#[derive(Deserialize)]
struct ForkPrContributorApprovalResponse {
    approval_policy: Option<String>,
}

#[derive(Deserialize)]
struct WorkflowPermsResponse {
    default_workflow_permissions: Option<String>,
}

#[derive(Deserialize)]
struct SecurityConfigDefault {
    default_for_new_repos: Option<String>,
    configuration: Option<SecurityConfigInner>,
}

#[derive(Deserialize)]
struct SecurityConfigInner {
    secret_scanning: Option<String>,
    secret_scanning_push_protection: Option<String>,
    dependabot_alerts: Option<String>,
}

#[derive(Deserialize)]
struct User {
    login: String,
}

impl OrgContext {
    pub async fn fetch(client: &Client, org: &str) -> Result<Self> {
        step("organization settings");
        let (two_factor_required, default_repository_permission) = match client
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
                (tfa, perm)
            }
            _ => (TwoFactorState::Unknown, DefaultRepoPermissionState::Unknown),
        };

        step("release immutability policy");
        let release_immutability = match client
            .get_json::<ImmutableReleasesResponse>(&format!(
                "/orgs/{org}/settings/immutable-releases"
            ))
            .await?
        {
            Fetch::Ok(r) => match r.enforced_repositories.as_deref() {
                Some("all") => ReleaseImmutabilityState::All,
                Some("selected") => ReleaseImmutabilityState::Selected,
                Some("none") => ReleaseImmutabilityState::None,
                _ => ReleaseImmutabilityState::Unknown,
            },
            _ => ReleaseImmutabilityState::Unknown,
        };

        step("fork PR contributor approval policy");
        let fork_pr_contributor_approval = match client
            .get_json::<ForkPrContributorApprovalResponse>(&format!(
                "/orgs/{org}/actions/permissions/fork-pr-contributor-approval"
            ))
            .await?
        {
            Fetch::Ok(r) => match r.approval_policy.as_deref() {
                Some("all_external_contributors") => {
                    ForkPrContributorApprovalState::AllExternalContributors
                }
                Some("first_time_contributors") => {
                    ForkPrContributorApprovalState::FirstTimeContributors
                }
                Some("first_time_contributors_new_to_github") => {
                    ForkPrContributorApprovalState::FirstTimeContributorsNewToGithub
                }
                Some(_) => ForkPrContributorApprovalState::Other,
                None => ForkPrContributorApprovalState::Unknown,
            },
            _ => ForkPrContributorApprovalState::Unknown,
        };

        step("default workflow token permissions");
        let workflow_token = match client
            .get_json::<WorkflowPermsResponse>(&format!("/orgs/{org}/actions/permissions/workflow"))
            .await?
        {
            Fetch::Ok(w) => match w.default_workflow_permissions.as_deref() {
                Some("read") => WorkflowTokenState::Read,
                Some(_) => WorkflowTokenState::Write,
                None => WorkflowTokenState::Unknown,
            },
            _ => WorkflowTokenState::Unknown,
        };

        step("default code security configuration");
        let (secret_scanning_default, push_protection_default, dependabot_alerts_default) =
            match client
                .get_json::<Vec<SecurityConfigDefault>>(&format!(
                    "/orgs/{org}/code-security/configurations/defaults"
                ))
                .await?
            {
                Fetch::Ok(defaults) => {
                    let chosen = defaults
                        .into_iter()
                        .find(|d| {
                            d.default_for_new_repos
                                .as_deref()
                                .is_some_and(|v| v != "none")
                        })
                        .and_then(|d| d.configuration);
                    match chosen {
                        Some(c) => (
                            feature_default(c.secret_scanning.as_deref()),
                            feature_default(c.secret_scanning_push_protection.as_deref()),
                            feature_default(c.dependabot_alerts.as_deref()),
                        ),
                        None => (
                            FeatureDefaultState::NotSet,
                            FeatureDefaultState::NotSet,
                            FeatureDefaultState::NotSet,
                        ),
                    }
                }
                _ => (
                    FeatureDefaultState::Unknown,
                    FeatureDefaultState::Unknown,
                    FeatureDefaultState::Unknown,
                ),
            };

        step("members without 2FA");
        let members_without_2fa =
            fetch_logins(client, &format!("/orgs/{org}/members?filter=2fa_disabled")).await?;
        step("outside collaborators");
        let outside_collaborators = fetch_outside_collaborators(client, org).await?;
        step("organization admins");
        let admins = fetch_logins(client, &format!("/orgs/{org}/members?role=admin")).await?;

        Ok(Self {
            two_factor_required,
            members_without_2fa,
            outside_collaborators,
            admins,
            default_repository_permission,
            release_immutability,
            fork_pr_contributor_approval,
            workflow_token,
            secret_scanning_default,
            push_protection_default,
            dependabot_alerts_default,
        })
    }
}

fn feature_default(value: Option<&str>) -> FeatureDefaultState {
    match value {
        Some("enabled") => FeatureDefaultState::Enabled,
        Some("disabled") => FeatureDefaultState::Disabled,
        Some("not_set") | None => FeatureDefaultState::NotSet,
        Some(_) => FeatureDefaultState::Unknown,
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
