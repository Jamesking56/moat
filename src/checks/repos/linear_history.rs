use super::context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "linear";
pub const DESCRIPTION: &str = "release branches require linear history (Settings → Branches → ruleset → Require linear history)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate(|state| match state {
        BranchProtectionState::Protected {
            required_linear_history,
            ..
        } => {
            if *required_linear_history {
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
