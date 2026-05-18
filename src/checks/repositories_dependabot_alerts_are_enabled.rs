use crate::checks::StateCtx;
use crate::checks::common::{FeatureState, feature_state_phrase};
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories dependabot alerts are enabled";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/security_products > Advanced Security > (__Click__ -> Set up or __Edit__ -> Existing one) > __Click__ -> Custom configuration > Dependency scanning > Dependabot alerts > __Select__ -> Enabled > __Click__ -> Save/Update configuration > __Click__ -> Pencil to edit configuration > Edit configuration > __Select__ -> Apply to: All repositories > __Select__ -> Default for new repositories: All > __Click__ -> Review > __Click__ -> Save and enable";
pub const WHY_ENABLE: &str = "Most package compromises are disclosed publicly before they are widely exploited; alerts tell you which of your repositories consume the bad version so you can pin or patch within the window before mass scanning catches up.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.dependabot_alerts_default.to_outcome("unknown")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.dependabot_alerts.to_outcome()
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let org_off = ctx
        .org
        .map(|o| !matches!(o.dependabot_alerts_default, FeatureDefaultState::Enabled));
    feature_state_phrase(
        "dependabot alerts",
        ctx.repos,
        |r| matches!(r.dependabot_alerts, FeatureState::Disabled),
        org_off,
    )
}
