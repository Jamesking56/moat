use super::context::{FeatureDefaultState, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "push protection";
pub const DESCRIPTION: &str = "org default code-security configuration enables secret scanning push protection for new repositories (Settings → Code security → Configurations)";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.push_protection_default {
        FeatureDefaultState::Enabled => CheckOutcome::pass("enabled"),
        FeatureDefaultState::Disabled => CheckOutcome::fail("disabled"),
        FeatureDefaultState::NotSet => CheckOutcome::warn("not set as default"),
        FeatureDefaultState::Unknown => CheckOutcome::skipped("n/a (plan)"),
    }
}
