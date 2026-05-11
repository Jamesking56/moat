use super::context::{DefaultRepoPermissionState, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "Default repo permission";

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
