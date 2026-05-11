use super::context::{OrgContext, TwoFactorState};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "2FA enforcement";
pub const DESCRIPTION: &str = "org requires every member to have two-factor authentication enabled (Settings → Authentication security → Require two-factor authentication)";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.two_factor_required {
        TwoFactorState::Required => CheckOutcome::pass("required"),
        TwoFactorState::NotRequired => CheckOutcome::fail("NOT required"),
        TwoFactorState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
