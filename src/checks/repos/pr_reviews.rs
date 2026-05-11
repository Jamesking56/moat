use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "PR";
pub const DESCRIPTION: &str =
    "default branch requires pull request reviews before merging (Settings → Branches → ruleset → Require a pull request before merging)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protection.flag_outcome(|_, pr| pr)
}
