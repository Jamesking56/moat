use super::context::{BranchProtectionState, FilePresence, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "owners";
pub const DESCRIPTION: &str = "CODEOWNERS file exists and the default branch requires code-owner review (Settings → Branches → ruleset → Require review from Code Owners)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    let file_present = match ctx.codeowners {
        FilePresence::Present => Some(true),
        FilePresence::Absent => Some(false),
        FilePresence::Unknown => None,
    };

    let required = match ctx.branch_protection {
        BranchProtectionState::Protected {
            require_code_owner_reviews,
            ..
        } => Some(require_code_owner_reviews),
        BranchProtectionState::Unprotected => Some(false),
        BranchProtectionState::NoDefaultBranch => return CheckOutcome::skipped("—"),
        BranchProtectionState::NoPermission => None,
    };

    match (file_present, required) {
        (Some(true), Some(true)) => CheckOutcome::pass("✓"),
        (Some(false), _) => CheckOutcome::fail("no file"),
        (_, Some(false)) => CheckOutcome::fail("not required"),
        _ => CheckOutcome::skipped("?"),
    }
}
