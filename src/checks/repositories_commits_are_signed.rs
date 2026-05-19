use crate::checks::StateCtx;
use crate::checks::common::ruleset_state_phrase;
use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories commits are signed";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/rules > (*Click* -> New ruleset -> New branch ruleset or *Edit* -> Existing one) > Enforcement status > *Select* -> Active > Target branches > *Add target* -> {branches} > Branch rules > *Check* -> Require signed commits > *Click* -> Create/Save changes";
pub const WHY_ENABLE: &str = "A stolen developer token can push commits authored as anyone; requiring a verified signature ties each commit to a key the attacker doesn't have, turning a leaked token from a code-push into a noisy failure.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.rulesets.required_signatures {
        CheckOutcome::pass("Required by an org-level ruleset")
    } else {
        CheckOutcome::fail("Not required by any org-level ruleset")
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate_flag(|s| match s {
        BranchProtectionState::Protected { signed_commits, .. } => Some(*signed_commits),
        _ => None,
    })
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let org_required = ctx.org.map(|o| o.rulesets.required_signatures);
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
