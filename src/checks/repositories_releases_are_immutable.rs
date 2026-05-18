use crate::checks::StateCtx;
use crate::checks::common::repos_word;
use crate::checks::org_context::{OrgContext, ReleaseImmutabilityState};
use crate::checks::repo_context::{ReleaseImmutabilityRepoState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories releases are immutable";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/repository-defaults > Releases > __Select__ -> All repositories";
pub const WHY_ENABLE: &str = "Without immutability, an existing tag can be moved or its assets replaced after the fact; downstream consumers pinned to a version they audited will silently fetch different bytes the next time they install.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.release_immutability {
        ReleaseImmutabilityState::All => CheckOutcome::pass("Enforced on all repositories"),
        ReleaseImmutabilityState::Selected => {
            CheckOutcome::warn("Enforced on selected repositories only")
        }
        ReleaseImmutabilityState::None => CheckOutcome::fail("Not enforced"),
        ReleaseImmutabilityState::Unknown => CheckOutcome::skipped("Unknown"),
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.release_immutability {
        ReleaseImmutabilityRepoState::Enabled => CheckOutcome::pass("✓"),
        ReleaseImmutabilityRepoState::Disabled => CheckOutcome::fail("✗"),
        ReleaseImmutabilityRepoState::Unknown => CheckOutcome::skipped("?"),
    }
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
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
    let org = ctx.org.and_then(|o| match o.release_immutability {
        ReleaseImmutabilityState::All => Some("all"),
        ReleaseImmutabilityState::Selected => Some("selected"),
        ReleaseImmutabilityState::None => Some("none"),
        ReleaseImmutabilityState::Unknown => None,
    });

    Some(match (org, disabled) {
        (Some("all"), 0) if total > 0 => format!(
            "immutable releases are enforced org-wide and on all {total} {}",
            repos_word(total)
        ),
        (Some("all"), n) => format!(
            "immutable releases are enforced org-wide, but {n}/{total} {} still allow tag and asset replacement",
            repos_word(total)
        ),
        (Some("selected"), n) => format!(
            "immutable releases are enforced on selected repositories only; {n}/{total} {} allow tag and asset replacement",
            repos_word(total)
        ),
        (Some("none"), 0) if total > 0 => format!(
            "immutable releases are not enforced org-wide, though all {total} {} have it enabled",
            repos_word(total)
        ),
        (Some("none"), n) if n > 0 => format!(
            "immutable releases are not enforced org-wide; {n}/{total} {} allow tag and asset replacement",
            repos_word(total)
        ),
        (Some("none"), _) => "immutable releases are not enforced org-wide".into(),
        (None, 0) if total > 0 => format!(
            "immutable releases are enabled on all {total} {}",
            repos_word(total)
        ),
        (None, n) if n > 0 => format!(
            "{n}/{total} {} allow tag and asset replacement",
            repos_word(total)
        ),
        _ => return None,
    })
}
