use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "deps";
pub const DESCRIPTION: &str =
    "Dependabot vulnerability alerts are enabled (Settings → Code security → Dependabot alerts)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.dependabot_alerts.to_outcome()
}
