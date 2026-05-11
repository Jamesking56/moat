use super::context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "linear";
pub const DESCRIPTION: &str = "default branch requires linear history and disallows force pushes and deletions (Settings → Branches → ruleset)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.branch_protection {
        BranchProtectionState::Protected {
            required_linear_history,
            allow_force_pushes,
            allow_deletions,
            ..
        } => {
            if required_linear_history && !allow_force_pushes && !allow_deletions {
                CheckOutcome::pass("✓")
            } else {
                let mut bad = Vec::new();
                if !required_linear_history {
                    bad.push("no linear history");
                }
                if allow_force_pushes {
                    bad.push("force pushes allowed");
                }
                if allow_deletions {
                    bad.push("deletions allowed");
                }
                CheckOutcome::fail("✗").with_items(bad.into_iter().map(String::from).collect())
            }
        }
        BranchProtectionState::Unprotected => CheckOutcome::fail("✗"),
        BranchProtectionState::NoDefaultBranch => CheckOutcome::skipped("—"),
        BranchProtectionState::NoPermission => CheckOutcome::skipped("?"),
    }
}
