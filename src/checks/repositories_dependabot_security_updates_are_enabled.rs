use crate::checks::StateCtx;
use crate::checks::common::feature_state_phrase;
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories Dependabot security updates are enabled";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/security_products > Advanced Security > (*Click* -> Set up or *Edit* -> Existing one) > *Click* -> Custom configuration > Dependency scanning > Dependabot alerts > Security updates > *Select* -> Enabled > *Click* -> Save/Update configuration > *Click* -> Pencil to edit configuration > Edit configuration > *Select* -> Apply to: All repositories > *Select* -> Default for new repositories: All > *Click* -> Review > *Click* -> Save and enable";
pub const HOW_TO_FIX_USER_ACCOUNT: &str = "https://github.com/{org}/{repo}/settings/security_analysis > Dependabot > Dependabot security updates > *Click* -> Enable";
pub const WHY_ENABLE: &str = "Alerts only tell you a vulnerable dependency is in use; security updates are what actually open the PR that bumps it. Without them, an alert sits in the dashboard until someone notices, and the window before mass scanning catches up is exactly the window you wanted to close.";

pub fn how_to_fix(ctx: StateCtx<'_>) -> &'static str {
    if ctx.org.is_none() {
        HOW_TO_FIX_USER_ACCOUNT
    } else {
        HOW_TO_FIX
    }
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.dependabot_security_updates_default.to_outcome()
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.dependabot_security_updates.to_outcome()
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let org_off = ctx.org.map(|o| {
        !matches!(
            o.dependabot_security_updates_default,
            FeatureDefaultState::Enabled
        )
    });
    feature_state_phrase(
        "Dependabot security updates",
        ctx.repos,
        |r| r.dependabot_security_updates,
        org_off,
    )
}
