use super::context::OrgContext;
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "Org admins";
pub const DESCRIPTION: &str = "owners with full control over the organization (People → filter by Owner) — keep this set as small as possible";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    ctx.admins
        .outcome(CheckOutcome::fail("none — org has no owner!"), |v| {
            CheckOutcome::warn(v.len().to_string())
        })
}
