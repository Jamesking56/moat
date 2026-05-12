use super::context::{FeatureDefaultState, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "secret push protection";
pub const DESCRIPTION: &str = "org default code-security configuration enables secret scanning push protection for new repositories (Settings → Code security → Configurations)";
pub const HOW_TO_FIX: &str =
    "github → organization → settings → code security → configurations → enable push protection by default";
pub const WHY_ENABLE: &str =
    "scanning finds secrets after they reach github; push protection rejects them at the git layer so the credential never enters history, forks, mirrors, or backups in the first place.";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.push_protection_default {
        FeatureDefaultState::Enabled => CheckOutcome::pass("enabled by default"),
        FeatureDefaultState::Disabled => CheckOutcome::fail("disabled"),
        FeatureDefaultState::NotSet => CheckOutcome::warn("not set as default"),
        FeatureDefaultState::Unknown => CheckOutcome::skipped("n/a (plan)"),
    }
}
