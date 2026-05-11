use super::context::{OrgContext, ReleaseImmutabilityState};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "release immutability";
pub const DESCRIPTION: &str = "org enforces immutable releases so published release assets and tags cannot be modified or replaced (Settings → Repository → Immutable releases)";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.release_immutability {
        ReleaseImmutabilityState::Enabled => CheckOutcome::pass("enabled"),
        ReleaseImmutabilityState::Disabled => CheckOutcome::fail("NOT enabled"),
        ReleaseImmutabilityState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
