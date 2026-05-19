use crate::checks::StateCtx;
use crate::checks::common::repos_word;
use crate::checks::org_context::{OrgContext, ReleaseImmutabilityState};
use crate::checks::repo_context::{ReleaseImmutabilityRepoState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories releases are immutable";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/repository-defaults > Releases > *Select* -> All repositories";
pub const HOW_TO_FIX_USER_ACCOUNT: &str = "https://github.com/{org}/{repo}/settings#releases > Releases > *Check* -> Immutable releases > *Click* -> Save";
pub const WHY_ENABLE: &str = "Without immutability, an existing tag can be moved or its assets replaced after the fact; downstream consumers pinned to a version they audited will silently fetch different bytes the next time they install.";

pub fn how_to_fix(ctx: StateCtx<'_>) -> &'static str {
    if ctx.org.is_none() {
        HOW_TO_FIX_USER_ACCOUNT
    } else {
        HOW_TO_FIX
    }
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.release_immutability {
        ReleaseImmutabilityState::All => CheckOutcome::pass("Enforced on all repositories"),
        ReleaseImmutabilityState::Selected => {
            CheckOutcome::warn("Enforced on selected repositories only")
        }
        ReleaseImmutabilityState::None => CheckOutcome::fail("Not enforced on any repository"),
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.release_immutability {
        ReleaseImmutabilityRepoState::Enabled => CheckOutcome::pass("✓"),
        ReleaseImmutabilityRepoState::Disabled => CheckOutcome::fail("✗"),
        ReleaseImmutabilityRepoState::PlanGated => CheckOutcome::skipped_plan_gated("N/A (plan)"),
    }
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    let disabled = ctx
        .repos
        .iter()
        .filter(|r| {
            matches!(
                r.release_immutability,
                ReleaseImmutabilityRepoState::Disabled
            )
        })
        .count();
    let org = ctx.org.map(|o| match o.release_immutability {
        ReleaseImmutabilityState::All => "all",
        ReleaseImmutabilityState::Selected => "selected",
        ReleaseImmutabilityState::None => "none",
    });

    if total == 0 {
        return None;
    }

    Some(match (org, disabled) {
        (Some("all"), 0) => format!(
            "immutable releases are enforced org-wide and on all {total} {}",
            repos_word(total)
        ),
        (Some("all"), n) => format!(
            "immutable releases are enforced org-wide, but {n} {} still allow tag and asset replacement",
            repos_word(n)
        ),
        (Some("selected"), n) => format!(
            "immutable releases are enforced on selected repositories only; {n} {} allow tag and asset replacement",
            repos_word(n)
        ),
        (Some("none"), 0) => format!(
            "immutable releases are not enforced org-wide, though all {total} {} have it enabled",
            repos_word(total)
        ),
        (Some("none"), n) => format!(
            "immutable releases are not enforced org-wide; {n} {} allow tag and asset replacement",
            repos_word(n)
        ),
        (None, 0) => format!(
            "immutable releases are enabled on all {total} {}",
            repos_word(total)
        ),
        (None, n) => format!("{n} {} allow tag and asset replacement", repos_word(n)),
        _ => return None,
    })
}
