use crate::checks::StateCtx;
use crate::checks::common::repos_word;
use crate::checks::org_context::{OrgContext, RulesetsState};
use crate::checks::repo_context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories release branches are protected";
pub const HOW_TO_FIX: &str = "GitHub → organization (or repository) → settings → rules → \"New ruleset\" → \"New branch ruleset\" → target your release branches (main, master, x.x) and set enforcement status to \"Active\".";
pub const WHY_ENABLE: &str = "Every other branch-level safeguard (signed commits, required reviews, linear history) hangs off a ruleset — with no ruleset attached to your release branches, none of those protections apply.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.rulesets.state == RulesetsState::NoPermission {
        return CheckOutcome::skipped("?");
    }
    if ctx.rulesets.any_active {
        CheckOutcome::pass("At least one active org-level ruleset")
    } else {
        CheckOutcome::fail("No active org-level rulesets")
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate(|state| match state {
        BranchProtectionState::Protected { .. } => BranchEval::Pass,
        BranchProtectionState::Unprotected => BranchEval::Fail(Vec::new()),
        BranchProtectionState::NoPermission => BranchEval::Unknown,
        BranchProtectionState::PlanGated => BranchEval::PlanGated,
    })
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    let unprotected = ctx
        .repos
        .iter()
        .filter(|r| {
            r.branch_protections
                .branches
                .iter()
                .any(|(_, s)| matches!(s, BranchProtectionState::Unprotected))
                || r.branch_protections.branches.is_empty()
        })
        .count();

    let org_active = ctx.org.and_then(|o| {
        if o.rulesets.state == RulesetsState::NoPermission {
            None
        } else {
            Some(o.rulesets.any_active)
        }
    });

    Some(match (org_active, unprotected) {
        (Some(true), 0) if total > 0 => format!(
            "release branches are protected by an active org-level ruleset and by branch protection on all {total} {}",
            repos_word(total)
        ),
        (Some(true), n) => format!(
            "an org-level ruleset is active, but {n}/{total} {} have unprotected release branches",
            repos_word(total)
        ),
        (Some(false), 0) if total > 0 => format!(
            "no active org-level rulesets, though release branches are protected across all {total} {}",
            repos_word(total)
        ),
        (Some(false), n) if n > 0 => format!(
            "no active org-level rulesets; {n}/{total} {} have unprotected release branches",
            repos_word(total)
        ),
        (Some(false), _) => "no active org-level rulesets".into(),
        (None, 0) if total > 0 => format!(
            "release branches are protected across all {total} {}",
            repos_word(total)
        ),
        (None, n) if n > 0 => format!(
            "{n}/{total} {} have unprotected release branches",
            repos_word(total)
        ),
        _ => return None,
    })
}
