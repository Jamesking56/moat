use crate::checks::repo_context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "protected release branches";
pub const HOW_TO_FIX: &str = "github → repository → settings → branches → add branch ruleset → target release branches (main, master, x.x).";
pub const WHY_ENABLE: &str = "every other branch-level safeguard (signed commits, required reviews, linear history) hangs off a ruleset — with no ruleset attached to your release branches, none of those protections apply.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate(|state| match state {
        BranchProtectionState::Protected { .. } => BranchEval::Pass,
        BranchProtectionState::Unprotected => BranchEval::Fail(Vec::new()),
        BranchProtectionState::NoPermission => BranchEval::Unknown,
        BranchProtectionState::PlanGated => BranchEval::PlanGated,
    })
}
