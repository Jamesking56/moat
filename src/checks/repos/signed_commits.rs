use super::context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "signed";
pub const DESCRIPTION: &str = "release branches require signed commits (Settings → Branches → ruleset → Require signed commits)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    if !ctx.private {
        return CheckOutcome::skipped("n/a");
    }
    ctx.branch_protections.aggregate(|state| match state {
        BranchProtectionState::Protected { signed_commits, .. } => {
            if *signed_commits {
                BranchEval::Pass
            } else {
                BranchEval::Fail(Vec::new())
            }
        }
        BranchProtectionState::Unprotected => BranchEval::Fail(Vec::new()),
        BranchProtectionState::NoPermission => BranchEval::Unknown,
        BranchProtectionState::PlanGated => BranchEval::PlanGated,
    })
}
