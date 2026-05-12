use super::context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "admins";
pub const DESCRIPTION: &str = "branch protection on release branches is enforced on admins (Settings → Branches → ruleset → Do not allow bypassing)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate(|state| match state {
        BranchProtectionState::Protected { enforce_admins, .. } => {
            if *enforce_admins {
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
