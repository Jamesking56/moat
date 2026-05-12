use super::context::{OrgContext, ReleaseImmutabilityState};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "release immutability";
pub const DESCRIPTION: &str = "org enforces immutable releases so published release assets and tags cannot be modified or replaced (Settings → Repository → Immutable releases)";
pub const HOW_TO_FIX: &str =
    "github → organization → settings → repository → immutable releases → all repositories";
pub const WHY_ENABLE: &str =
    "without immutability, an existing tag can be moved or its assets replaced after the fact; downstream consumers pinned to a version they audited will silently fetch different bytes the next time they install.";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.release_immutability {
        ReleaseImmutabilityState::All => CheckOutcome::pass("enforced on all repositories"),
        ReleaseImmutabilityState::Selected => {
            CheckOutcome::warn("enforced on selected repositories only")
        }
        ReleaseImmutabilityState::None => CheckOutcome::fail("not enforced"),
        ReleaseImmutabilityState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
