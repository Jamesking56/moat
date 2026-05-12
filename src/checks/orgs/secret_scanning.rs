use super::context::{FeatureDefaultState, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "secret scanning";
pub const DESCRIPTION: &str = "org default code-security configuration enables secret scanning for new repositories (Settings → Code security → Configurations)";
pub const HOW_TO_FIX: &str =
    "github → organization → settings → code security → configurations → enable secret scanning by default";
pub const WHY_ENABLE: &str =
    "secrets accidentally committed stay valid until someone notices; scanning gives you minutes-to-hours warning instead of waiting for a leaked-credential abuse alert from a downstream provider.";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.secret_scanning_default {
        FeatureDefaultState::Enabled => CheckOutcome::pass("enabled by default"),
        FeatureDefaultState::Disabled => CheckOutcome::fail("disabled"),
        FeatureDefaultState::NotSet => CheckOutcome::warn("not set as default"),
        FeatureDefaultState::Unknown => CheckOutcome::skipped("n/a (plan)"),
    }
}
