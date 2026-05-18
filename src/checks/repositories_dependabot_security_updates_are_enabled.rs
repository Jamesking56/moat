use crate::checks::StateCtx;
use crate::checks::common::{FeatureState, feature_state_phrase};
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories dependabot security updates are enabled";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/security_products > Advanced Security > (__Click__ -> Set up or __Edit__ -> Existing one) > __Click__ -> Custom configuration > Dependency scanning > Dependabot alerts > Security updates > __Select__ -> Enabled > __Click__ -> Save/Update configuration > __Click__ -> Pencil to edit configuration > Edit configuration > __Select__ -> Apply to: All repositories > __Select__ -> Default for new repositories: All > __Click__ -> Review > __Click__ -> Save and enable";
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
