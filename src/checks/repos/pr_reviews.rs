use super::context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "PR";
pub const DESCRIPTION: &str = "release branches require pull request reviews before merging (Settings → Branches → ruleset → Require a pull request before merging)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate(|state| match state {
        BranchProtectionState::Protected { pr_reviews, .. } => {
            if *pr_reviews {
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
