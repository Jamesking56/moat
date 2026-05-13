use crate::checks::StateCtx;
use crate::checks::common::ruleset_state_phrase;
use crate::checks::org_context::{OrgContext, RulesetsState};
use crate::checks::repo_context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "signed commits";
pub const HOW_TO_FIX: &str = "GitHub → organization (or repository) → settings → rules → edit the ruleset for your release branches → under \"Rules\", enable \"Require signed commits\".";
pub const WHY_ENABLE: &str = "a stolen developer token can push commits authored as anyone; requiring a verified signature ties each commit to a key the attacker doesn't have, turning a leaked token from a code-push into a noisy failure.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.rulesets.state == RulesetsState::NoPermission {
        return CheckOutcome::skipped("?");
    }
    if ctx.rulesets.required_signatures {
        CheckOutcome::pass("required by an org-level ruleset")
    } else {
        CheckOutcome::fail("not required by any org-level ruleset")
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate_flag(|s| match s {
        BranchProtectionState::Protected { signed_commits, .. } => Some(*signed_commits),
        _ => None,
    })
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let org_required = ctx.org.and_then(|o| {
        if o.rulesets.state == RulesetsState::NoPermission {
            None
        } else {
            Some(o.rulesets.required_signatures)
        }
    });
    ruleset_state_phrase(
        "signed commits",
        ctx.repos,
        |s| match s {
            BranchProtectionState::Protected { signed_commits, .. } => Some(*signed_commits),
            _ => None,
        },
        org_required,
    )
}
