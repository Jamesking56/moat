use super::context::OrgContext;
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "Members without 2FA";
pub const DESCRIPTION: &str = "lists org members whose account does not have two-factor authentication enabled (each one is an account-takeover risk)";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    ctx.members_without_2fa
        .outcome(CheckOutcome::pass("none"), |v| {
            CheckOutcome::fail(format!("{} found", v.len()))
        })
}
