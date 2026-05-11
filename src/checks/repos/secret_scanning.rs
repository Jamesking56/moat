use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "scan";
pub const DESCRIPTION: &str =
    "secret scanning is enabled (Settings → Code security → Secret scanning)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.secret_scanning.to_outcome()
}
