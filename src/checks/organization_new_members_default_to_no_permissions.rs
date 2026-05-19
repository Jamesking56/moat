use crate::checks::StateCtx;
use crate::checks::org_context::{DefaultRepoPermissionState, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Organization new members default to no permissions";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/member_privileges > Base permissions > *Select* -> No permission -> *Click* -> Change base permission to \"No permission\"";
pub const WHY_ENABLE: &str = "This setting decides the blast radius of a single compromised account; with write or admin as the default, one stolen session can push to every repo at once instead of just the ones that member legitimately touches.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    match &ctx.default_repository_permission {
        DefaultRepoPermissionState::None => {
            CheckOutcome::pass("New members get no access to repositories by default")
        }
        DefaultRepoPermissionState::Read => {
            CheckOutcome::pass("New members get read access by default")
        }
        DefaultRepoPermissionState::Write => {
            CheckOutcome::fail("New members get write access to every repository by default")
        }
        DefaultRepoPermissionState::Admin => {
            CheckOutcome::fail("New members get admin access to every repository by default")
        }
        DefaultRepoPermissionState::Other(s) => {
            CheckOutcome::warn(format!("Unrecognized default permission: {s}"))
        }
    }
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let org = ctx.org?;
    Some(match &org.default_repository_permission {
        DefaultRepoPermissionState::None => {
            "new members get no access to any repository by default".into()
        }
        DefaultRepoPermissionState::Read => {
            "new members can read every repository by default".into()
        }
        DefaultRepoPermissionState::Write => {
            "new members can push to every repository by default".into()
        }
        DefaultRepoPermissionState::Admin => {
            "new members are admins on every repository by default".into()
        }
        DefaultRepoPermissionState::Other(s) => {
            format!("default repository permission is set to `{s}`")
        }
    })
}
