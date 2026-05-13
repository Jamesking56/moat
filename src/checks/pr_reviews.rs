use crate::checks::repo_context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "pull request reviews";
pub const HOW_TO_FIX: &str = "github → repository → settings → rules → edit the ruleset for your release branches → under \"Rules\", enable \"Require a pull request before merging\" and set required approvals to 1 or more.";
pub const WHY_ENABLE: &str = "without required reviews, a single compromised contributor account can push directly to a release branch — peer review is the cheapest mechanism that catches malicious patches before they ship.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate_flag(|s| match s {
        BranchProtectionState::Protected { pr_reviews, .. } => Some(*pr_reviews),
        _ => None,
    })
}
