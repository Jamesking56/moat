use crate::checks::StateCtx;
use crate::checks::common::{count_repos_missing_branch_flag, repos_word};
use crate::checks::org_context::{OrgContext, RulesetsState};
use crate::checks::repo_context::{BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "repositories branch protection applies to admins";
pub const HOW_TO_FIX: &str = "GitHub → organization (or repository) → settings → rules → edit the ruleset for your release branches → under \"Bypass list\", remove every role/team/user.";
pub const WHY_ENABLE: &str = "if admins can bypass the ruleset, a single compromised admin token is enough to push unsigned or unreviewed code straight to a release branch — the rule becomes advisory.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.rulesets.state == RulesetsState::NoPermission {
        return CheckOutcome::skipped("?");
    }
    if !ctx.rulesets.any_active {
        return CheckOutcome::fail("no active org-level rulesets");
    }
    if ctx.rulesets.has_bypass_actors {
        CheckOutcome::fail("bypass actors configured on org-level rulesets")
    } else {
        CheckOutcome::pass("enforced for everyone (no bypass actors)")
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate_flag(|s| match s {
        BranchProtectionState::Protected { enforce_admins, .. } => Some(*enforce_admins),
        _ => None,
    })
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    let bypass_repos = count_repos_missing_branch_flag(ctx.repos, |s| match s {
        BranchProtectionState::Protected { enforce_admins, .. } => Some(*enforce_admins),
        _ => None,
    });

    let org_state = ctx.org.and_then(|o| {
        if o.rulesets.state == RulesetsState::NoPermission {
            None
        } else if !o.rulesets.any_active {
            Some("no_rulesets")
        } else if o.rulesets.has_bypass_actors {
            Some("bypass")
        } else {
            Some("clean")
        }
    });

    Some(match (org_state, bypass_repos) {
        (Some("clean"), 0) if total > 0 => format!(
            "no actor can bypass org-level rulesets and admin enforcement is on across all {total} {}",
            repos_word(total)
        ),
        (Some("clean"), n) => format!(
            "no actor can bypass org-level rulesets, but {n}/{total} {} let admins bypass repo branch protection",
            repos_word(total)
        ),
        (Some("bypass"), 0) if total > 0 => format!(
            "org-level rulesets allow bypass actors; every release branch across {total} {} still enforces admin restrictions",
            repos_word(total)
        ),
        (Some("bypass"), n) => format!(
            "org-level rulesets allow bypass actors and {n}/{total} {} let admins bypass repo branch protection",
            repos_word(total)
        ),
        (Some("no_rulesets"), 0) if total > 0 => format!(
            "no active org-level rulesets, though admin enforcement is on across all {total} {}",
            repos_word(total)
        ),
        (Some("no_rulesets"), n) if n > 0 => format!(
            "no active org-level rulesets; {n}/{total} {} let admins bypass repo branch protection",
            repos_word(total)
        ),
        (Some("no_rulesets"), _) => "no active org-level rulesets".into(),
        (None, 0) if total > 0 => format!(
            "admin enforcement is on for every release branch across all {total} {}",
            repos_word(total)
        ),
        (None, n) if n > 0 => format!(
            "{n}/{total} {} let admins bypass branch protection",
            repos_word(total)
        ),
        _ => return None,
    })
}
