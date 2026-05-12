use super::context::{OrgContext, TwoFactorState};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "2FA authentication";
pub const DESCRIPTION: &str = "org requires every member to have two-factor authentication enabled (Settings → Authentication security → Require two-factor authentication)";
pub const HOW_TO_FIX: &str =
    "github → organization → settings → authentication security → require two-factor authentication";
pub const WHY_ENABLE: &str =
    "stolen passwords are the entry point of most maintainer-account compromises; enforcing 2FA org-wide raises the cost of a takeover from a phishing email to a physical device.";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.two_factor_required {
        TwoFactorState::Required => CheckOutcome::pass("required for every member"),
        TwoFactorState::NotRequired => CheckOutcome::fail("not required"),
        TwoFactorState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
