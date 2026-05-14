use crate::checks::StateCtx;
use crate::checks::common::ruleset_state_phrase;
use crate::checks::org_context::{OrgContext, RulesetsState};
use crate::checks::repo_context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories default branch has linear history";
pub const HOW_TO_FIX: &str = "GitHub → organization (or repository) → settings → rules → edit the ruleset for your release branches → under \"Rules\", enable \"Require linear history\".";
pub const WHY_ENABLE: &str = "Merge commits can hide unreviewed parents — a `git merge` of an unprotected side branch can introduce code that no reviewer ever saw, while still appearing as a normal merge in the PR.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.rulesets.state == RulesetsState::NoPermission {
        return CheckOutcome::skipped("?");
    }
    if ctx.rulesets.required_linear_history {
        CheckOutcome::pass("Required by an org-level ruleset")
    } else {
        CheckOutcome::fail("Not required by any org-level ruleset")
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate_flag(|s| match s {
        BranchProtectionState::Protected {
            required_linear_history,
            ..
        } => Some(*required_linear_history),
        _ => None,
    })
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let org_required = ctx.org.and_then(|o| {
        if o.rulesets.state == RulesetsState::NoPermission {
            None
        } else {
            Some(o.rulesets.required_linear_history)
        }
    });
    ruleset_state_phrase(
        "linear history",
        ctx.repos,
        |s| match s {
            BranchProtectionState::Protected {
                required_linear_history,
                ..
            } => Some(*required_linear_history),
            _ => None,
        },
        org_required,
    )
}
