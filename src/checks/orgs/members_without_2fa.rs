use super::context::OrgContext;
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "Members without 2FA";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    ctx.members_without_2fa.outcome(CheckOutcome::pass("none"), |v| {
        CheckOutcome::fail(format!("{} found", v.len()))
    })
}
