use crate::checks::StateCtx;
use crate::checks::common::ruleset_state_phrase;
use crate::checks::org_context::{OrgContext, RulesetsState};
use crate::checks::repo_context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "repositories pull requests require reviews";
pub const HOW_TO_FIX: &str = "GitHub → organization (or repository) → settings → rules → edit the ruleset for your release branches → under \"Rules\", enable \"Require a pull request before merging\" and set required approvals to 1 or more.";
pub const WHY_ENABLE: &str = "without required reviews, a single compromised contributor account can push directly to a release branch — peer review is the cheapest mechanism that catches malicious patches before they ship.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.rulesets.state == RulesetsState::NoPermission {
        return CheckOutcome::skipped("?");
    }
    if ctx.rulesets.pull_request {
        CheckOutcome::pass("required by an org-level ruleset")
    } else {
        CheckOutcome::fail("not required by any org-level ruleset")
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate_flag(|s| match s {
        BranchProtectionState::Protected { pr_reviews, .. } => Some(*pr_reviews),
        _ => None,
    })
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let org_required = ctx.org.and_then(|o| {
        if o.rulesets.state == RulesetsState::NoPermission {
            None
        } else {
            Some(o.rulesets.pull_request)
        }
    });
    ruleset_state_phrase(
        "pull request reviews",
        ctx.repos,
        |s| match s {
            BranchProtectionState::Protected { pr_reviews, .. } => Some(*pr_reviews),
            _ => None,
        },
        org_required,
    )
}
