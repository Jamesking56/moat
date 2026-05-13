use crate::checks::org_context::{OrgContext, TwoFactorState};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "2FA authentication";
pub const HOW_TO_FIX: &str = "github → your organization → settings → authentication security → under \"two-factor authentication\", enable both \"require two-factor authentication for everyone in the <org> organization\" and \"only allow secure two-factor methods\".";
pub const WHY_ENABLE: &str = "stolen passwords are the entry point of most maintainer-account compromises; enforcing 2FA org-wide raises the cost of a takeover from a phishing email to a physical device.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.two_factor_required {
        TwoFactorState::Required => CheckOutcome::pass("required for every member"),
        TwoFactorState::NotRequired => CheckOutcome::fail("not required"),
        TwoFactorState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
