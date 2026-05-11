use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "signed";
pub const DESCRIPTION: &str =
    "default branch requires signed commits (Settings → Branches → ruleset → Require signed commits)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protection.flag_outcome(|signed, _| signed)
}
