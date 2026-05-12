use super::context::OrgContext;
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "members missing 2FA";
pub const DESCRIPTION: &str = "lists org members whose account does not have two-factor authentication enabled (each one is an account-takeover risk)";
pub const HOW_TO_FIX: &str =
    "ask each member to enable two-factor authentication on their github account";
pub const WHY_ENABLE: &str =
    "the org-wide 2FA policy only covers members enrolled after it was turned on; anyone here predates it and remains the weakest unlocked door into the org.";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    ctx.members_without_2fa
        .outcome(CheckOutcome::pass("none"), |v| {
            CheckOutcome::fail(format!("{} member(s) without 2FA", v.len()))
        })
}
