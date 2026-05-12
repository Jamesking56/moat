use super::context::{DefaultRepoPermissionState, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "new members default permission";
pub const DESCRIPTION: &str = "base permission every org member gets on every org repo (Settings → Member privileges → Base permissions) — should be none or read";
pub const HOW_TO_FIX: &str =
    "github → organization → settings → member privileges → base permissions → none or read";
pub const WHY_ENABLE: &str =
    "this setting decides the blast radius of a single compromised account; with write or admin as the default, one stolen session can push to every repo at once instead of just the ones that member legitimately touches.";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match &ctx.default_repository_permission {
        DefaultRepoPermissionState::None => CheckOutcome::pass("none"),
        DefaultRepoPermissionState::Read => CheckOutcome::pass("read"),
        DefaultRepoPermissionState::Write => {
            CheckOutcome::fail("write — every member can push to every repo")
        }
        DefaultRepoPermissionState::Admin => {
            CheckOutcome::fail("admin — every member is an admin on every repo")
        }
        DefaultRepoPermissionState::Other(s) => CheckOutcome::warn(s.clone()),
        DefaultRepoPermissionState::Unknown => CheckOutcome::skipped("(requires org admin token)"),
    }
}
