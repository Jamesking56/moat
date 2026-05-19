use crate::checks::StateCtx;
use crate::checks::common::feature_state_phrase;
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories Dependabot alerts are enabled";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/security_products > Advanced Security > (*Click* -> Set up or *Edit* -> Existing one) > *Click* -> Custom configuration > Dependency scanning > Dependabot alerts > *Select* -> Enabled > *Click* -> Save/Update configuration > *Click* -> Pencil to edit configuration > Edit configuration > *Select* -> Apply to: All repositories > *Select* -> Default for new repositories: All > *Click* -> Review > *Click* -> Save and enable";
pub const HOW_TO_FIX_USER_ACCOUNT: &str = "https://github.com/{org}/{repo}/settings/security_analysis > Dependabot > Dependabot alerts > *Click* -> Enable";
pub const WHY_ENABLE: &str = "Most package compromises are disclosed publicly before they are widely exploited; alerts tell you which of your repositories consume the bad version so you can pin or patch within the window before mass scanning catches up.";

pub fn how_to_fix(ctx: StateCtx<'_>) -> &'static str {
    if ctx.org.is_none() {
        HOW_TO_FIX_USER_ACCOUNT
    } else {
        HOW_TO_FIX
    }
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.dependabot_alerts_default.to_outcome()
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.dependabot_alerts.to_outcome()
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let org_off = ctx
        .org
        .map(|o| !matches!(o.dependabot_alerts_default, FeatureDefaultState::Enabled));
    feature_state_phrase(
        "Dependabot alerts",
        ctx.repos,
        |r| r.dependabot_alerts,
        org_off,
    )
}
