use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "scan";
pub const DESCRIPTION: &str =
    "secret scanning is enabled (Settings → Code security → Secret scanning)";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → code security → secret scanning → enable";
pub const WHY_ENABLE: &str =
    "even with push protection, secrets get committed in private history that later goes public, in old branches, and in PRs from forks — scanning surfaces them so you can rotate before someone else finds them.";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.secret_scanning.to_outcome()
}
