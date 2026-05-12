use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "deps";
pub const DESCRIPTION: &str =
    "Dependabot vulnerability alerts are enabled (Settings → Code security → Dependabot alerts)";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → code security → dependabot alerts → enable";
pub const WHY_ENABLE: &str =
    "most package compromises are disclosed publicly before they are widely exploited; alerts tell you exactly which of your repos consume the bad version so you can pin or patch within the window before mass scanning catches up.";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.dependabot_alerts.to_outcome()
}
