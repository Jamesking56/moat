use super::context::{FeatureDefaultState, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "dependabot alerts";
pub const DESCRIPTION: &str = "org default code-security configuration enables Dependabot alerts for new repositories (Settings → Code security → Configurations)";
pub const HOW_TO_FIX: &str =
    "github → organization → settings → code security → configurations → enable dependabot alerts by default";
pub const WHY_ENABLE: &str =
    "most package compromises are disclosed publicly before they are widely exploited; alerts tell you which of your repos consume the bad version so you can pin or patch within the window before mass scanning catches up.";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.dependabot_alerts_default {
        FeatureDefaultState::Enabled => CheckOutcome::pass("enabled by default"),
        FeatureDefaultState::Disabled => CheckOutcome::fail("disabled"),
        FeatureDefaultState::NotSet => CheckOutcome::warn("not set as default"),
        FeatureDefaultState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
