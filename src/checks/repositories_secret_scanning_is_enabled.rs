use crate::checks::StateCtx;
use crate::checks::common::{FeatureState, feature_state_phrase};
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories secret scanning is enabled";
pub const HOW_TO_FIX: &str = "GitHub → your organization → settings → advanced security → configurations → open the configuration that enables \"Secret scanning\" → under \"Policy\", set \"Use as default for newly created repositories\" to apply to your repositories → Save configuration (per-repo: either apply a configuration that enables it — org settings → advanced security → configurations → next to the configuration, click \"Apply to\" and select the repo — or open the repo directly: settings → advanced security → enable \"Secret scanning\").";
pub const WHY_ENABLE: &str = "Secrets accidentally committed stay valid until someone notices; scanning gives you minutes-to-hours warning instead of waiting for a leaked-credential abuse alert from a downstream provider.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.secret_scanning_default.to_outcome("n/a (plan)")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.secret_scanning.to_outcome()
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let org_off = ctx
        .org
        .map(|o| !matches!(o.secret_scanning_default, FeatureDefaultState::Enabled));
    feature_state_phrase(
        "secret scanning",
        ctx.repos,
        |r| matches!(r.secret_scanning, FeatureState::Disabled),
        org_off,
    )
}
