use crate::support::github::{Client, Fetch};
use crate::support::outcome::CheckOutcome;
use anyhow::Result;
use serde::Deserialize;

pub struct OrgContext {
    pub two_factor_required: TwoFactorState,
    pub members_without_2fa: MemberList,
    pub outside_collaborators: MemberList,
    pub admins: MemberList,
    pub default_repository_permission: DefaultRepoPermissionState,
}

#[derive(Clone, Copy)]
pub enum TwoFactorState {
    Required,
    NotRequired,
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
struct User {
    login: String,
}

impl OrgContext {
    pub async fn fetch(client: &Client, org: &str) -> Result<Self> {
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

        let members_without_2fa =
            fetch_logins(client, &format!("/orgs/{org}/members?filter=2fa_disabled")).await?;
        let outside_collaborators =
            fetch_logins(client, &format!("/orgs/{org}/outside_collaborators")).await?;
        let admins = fetch_logins(client, &format!("/orgs/{org}/members?role=admin")).await?;

        Ok(Self {
            two_factor_required,
            members_without_2fa,
            outside_collaborators,
            admins,
            default_repository_permission,
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
