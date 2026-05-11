use super::context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "admins";
pub const DESCRIPTION: &str = "branch protection on the default branch is enforced on admins (Settings → Branches → ruleset → Do not allow bypassing)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.branch_protection {
        BranchProtectionState::Protected { enforce_admins, .. } => {
            if enforce_admins {
                CheckOutcome::pass("✓")
            } else {
                CheckOutcome::fail("✗")
            }
        }
        BranchProtectionState::Unprotected => CheckOutcome::fail("✗"),
        BranchProtectionState::NoDefaultBranch => CheckOutcome::skipped("—"),
        BranchProtectionState::NoPermission => CheckOutcome::skipped("?"),
    }
}
