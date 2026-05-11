use super::context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "protected branch";
pub const DESCRIPTION: &str =
    "default branch has a protection rule (Settings → Branches → Add branch ruleset)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.branch_protection {
        BranchProtectionState::Protected { .. } => CheckOutcome::pass("✓"),
        BranchProtectionState::Unprotected => CheckOutcome::fail("✗"),
        BranchProtectionState::NoDefaultBranch => CheckOutcome::skipped("—"),
        BranchProtectionState::NoPermission => CheckOutcome::skipped("?"),
    }
}
