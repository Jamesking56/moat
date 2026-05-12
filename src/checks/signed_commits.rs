use crate::checks::repo_context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "signed commits";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → branches → edit ruleset → require signed commits.";
pub const WHY_ENABLE: &str = "a stolen developer token can push commits authored as anyone; requiring a verified signature ties each commit to a key the attacker doesn't have, turning a leaked token from a code-push into a noisy failure.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate_flag(|s| match s {
        BranchProtectionState::Protected { signed_commits, .. } => Some(*signed_commits),
        _ => None,
    })
}
