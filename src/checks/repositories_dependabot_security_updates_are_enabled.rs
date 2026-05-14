use crate::checks::StateCtx;
use crate::checks::common::{FeatureState, feature_state_phrase};
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories dependabot security updates are enabled";
pub const HOW_TO_FIX: &str = "GitHub → your organization → settings → advanced security → configurations → open the configuration that enables \"dependabot security updates\" → under \"Policy\", set \"Use as default for newly created repositories\" to apply to your repositories → Save configuration (per-repo: either apply a configuration that enables it — org settings → advanced security → configurations → next to the configuration, click \"Apply to\" and select the repo — or open the repo directly: settings → advanced security → \"dependabot security updates\" → Enable).";
pub const WHY_ENABLE: &str = "Alerts only tell you a vulnerable dependency is in use; security updates are what actually open the PR that bumps it. Without them, an alert sits in the dashboard until someone notices, and the window before mass scanning catches up is exactly the window you wanted to close.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.dependabot_security_updates_default
        .to_outcome("unknown")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.dependabot_security_updates.to_outcome()
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let org_off = ctx.org.map(|o| {
        !matches!(
            o.dependabot_security_updates_default,
            FeatureDefaultState::Enabled
        )
    });
    feature_state_phrase(
        "dependabot security updates",
        ctx.repos,
        |r| matches!(r.dependabot_security_updates, FeatureState::Disabled),
        org_off,
    )
}
