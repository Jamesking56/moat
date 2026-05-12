use super::context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "PR";
pub const DESCRIPTION: &str = "release branches require pull request reviews before merging (Settings → Branches → ruleset → Require a pull request before merging)";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → branches → edit ruleset → require a pull request before merging → 1+ reviewer";
pub const WHY_ENABLE: &str =
    "without required reviews, a single compromised contributor account can push directly to a release branch — peer review is the cheapest mechanism that catches malicious patches before they ship.";

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
