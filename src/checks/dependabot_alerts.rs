use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "dependabot alerts";
pub const HOW_TO_FIX: &str = "github → your organization → settings → advanced security → configurations → edit the default configuration → under \"Dependency scanning\", set \"Dependabot alerts\" to \"Enabled\" (per-repo: repo → settings → advanced security → \"Dependabot alerts\" → Enable).";
pub const WHY_ENABLE: &str = "most package compromises are disclosed publicly before they are widely exploited; alerts tell you which of your repos consume the bad version so you can pin or patch within the window before mass scanning catches up.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.dependabot_alerts_default.to_outcome("unknown")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.dependabot_alerts.to_outcome()
}
