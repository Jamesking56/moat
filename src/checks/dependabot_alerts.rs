use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "dependabot alerts";
pub const HOW_TO_FIX: &str = "github → organization → settings → code security → configurations → enable dependabot alerts by default (and per-repo: settings → code security → dependabot alerts → enable).";
pub const WHY_ENABLE: &str = "most package compromises are disclosed publicly before they are widely exploited; alerts tell you which of your repos consume the bad version so you can pin or patch within the window before mass scanning catches up.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.dependabot_alerts_default.to_outcome("unknown")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.dependabot_alerts.to_outcome()
}
