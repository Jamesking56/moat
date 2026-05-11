use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "push";
pub const DESCRIPTION: &str =
    "push protection blocks commits containing secrets (Settings → Code security → Push protection)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.push_protection.to_outcome()
}
