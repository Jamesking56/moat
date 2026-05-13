use crate::checks::StateCtx;
use crate::checks::common::{FeatureState, feature_state_phrase};
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "dependabot alerts";
pub const HOW_TO_FIX: &str = "GitHub → your organization → settings → advanced security → configurations → open the configuration that enables \"dependabot alerts\" → under \"Policy\", set \"Use as default for newly created repositories\" to apply to your repositories → Save configuration (per-repo: either apply a configuration that enables it — org settings → advanced security → configurations → next to the configuration, click \"Apply to\" and select the repo — or open the repo directly: settings → advanced security → \"dependabot alerts\" → Enable).";
pub const WHY_ENABLE: &str = "most package compromises are disclosed publicly before they are widely exploited; alerts tell you which of your repos consume the bad version so you can pin or patch within the window before mass scanning catches up.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.dependabot_alerts_default.to_outcome("unknown")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.dependabot_alerts.to_outcome()
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let org_off = ctx.org.map(|o| {
        !matches!(o.dependabot_alerts_default, FeatureDefaultState::Enabled)
    });
    feature_state_phrase(
        "dependabot alerts",
        ctx.repos,
        |r| matches!(r.dependabot_alerts, FeatureState::Disabled),
        org_off,
    )
}
