use crate::checks::org_context::{OrgContext, ReleaseImmutabilityState};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "release immutability";
pub const HOW_TO_FIX: &str = "github → your organization → settings → repository → general → under \"Releases\", set immutable releases to \"All repositories\".";
pub const WHY_ENABLE: &str = "without immutability, an existing tag can be moved or its assets replaced after the fact; downstream consumers pinned to a version they audited will silently fetch different bytes the next time they install.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.release_immutability {
        ReleaseImmutabilityState::All => CheckOutcome::pass("enforced on all repositories"),
        ReleaseImmutabilityState::Selected => {
            CheckOutcome::warn("enforced on selected repositories only")
        }
        ReleaseImmutabilityState::None => CheckOutcome::fail("not enforced"),
        ReleaseImmutabilityState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
