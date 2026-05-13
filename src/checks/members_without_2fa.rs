use crate::checks::org_context::OrgContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "members missing 2FA";
pub const HOW_TO_FIX: &str = "github → your organization → people → filter by \"two-factor:disabled\" → ask each listed member to enable two-factor authentication on their github account (user settings → password and authentication).";
pub const WHY_ENABLE: &str = "the org-wide 2FA policy only covers members enrolled after it was turned on; anyone here predates it and remains the weakest unlocked door into the org.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.members_without_2fa
        .outcome(CheckOutcome::pass("none"), |v| {
            CheckOutcome::fail(format!("{} member(s) without 2FA", v.len()))
        })
}
