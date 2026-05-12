use super::context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "signed";
pub const DESCRIPTION: &str = "release branches require signed commits (Settings → Branches → ruleset → Require signed commits)";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → branches → edit ruleset → require signed commits";
pub const WHY_ENABLE: &str =
    "a stolen developer token can push commits authored as anyone; requiring a verified signature ties each commit to a key the attacker doesn't have, turning a leaked token from a code-push into a noisy failure.";

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
