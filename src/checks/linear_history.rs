use crate::checks::repo_context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "linear history";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → branches → edit ruleset → require linear history.";
pub const WHY_ENABLE: &str = "merge commits can hide unreviewed parents — a `git merge` of an unprotected side branch can introduce code that no reviewer ever saw, while still appearing as a normal merge in the PR.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate_flag(|s| match s {
        BranchProtectionState::Protected {
            required_linear_history,
            ..
        } => Some(*required_linear_history),
        _ => None,
    })
}
