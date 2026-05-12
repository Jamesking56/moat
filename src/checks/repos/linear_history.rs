use super::context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "linear";
pub const DESCRIPTION: &str = "release branches require linear history (Settings → Branches → ruleset → Require linear history)";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → branches → edit ruleset → require linear history";
pub const WHY_ENABLE: &str =
    "merge commits can hide unreviewed parents — a `git merge` of an unprotected side branch can introduce code that no reviewer ever saw, while still appearing as a normal merge in the PR.";

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
