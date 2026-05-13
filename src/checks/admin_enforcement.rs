use crate::checks::repo_context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "admin enforcement";
pub const HOW_TO_FIX: &str = "github → repository → settings → rules → edit the ruleset for your release branches → under \"Bypass list\", remove every role/team/user.";
pub const WHY_ENABLE: &str = "if admins can bypass the ruleset, a single compromised admin token is enough to push unsigned or unreviewed code straight to a release branch — the rule becomes advisory.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate_flag(|s| match s {
        BranchProtectionState::Protected { enforce_admins, .. } => Some(*enforce_admins),
        _ => None,
    })
}
