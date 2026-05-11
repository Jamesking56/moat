use super::context::OrgContext;
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "Outside collaborators";
pub const DESCRIPTION: &str = "non-members granted write/admin access to private repos or elevated access on public repos (People → Outside collaborators)";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    ctx.outside_collaborators
        .outcome(CheckOutcome::pass("none"), |v| {
            CheckOutcome::warn(v.len().to_string())
        })
}
