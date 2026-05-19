use crate::checks::StateCtx;
use crate::checks::common::feature_state_phrase;
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories secret scanning is enabled";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/security_products > Advanced Security > (*Click* -> Set up or *Edit* -> Existing one) > Secret scanning > *Select* -> Enabled > *Click* -> Review > Set up Advanced Security > *Click* -> Save and apply/enable";
pub const HOW_TO_FIX_USER_ACCOUNT: &str = "https://github.com/{org}/{repo}/settings/security_analysis > Secret scanning > *Click* -> Enable";
pub const WHY_ENABLE: &str = "Secrets accidentally committed stay valid until someone notices; scanning gives you minutes-to-hours warning instead of waiting for a leaked-credential abuse alert from a downstream provider.";

pub fn how_to_fix(ctx: StateCtx<'_>) -> &'static str {
    if ctx.org.is_none() {
        HOW_TO_FIX_USER_ACCOUNT
    } else {
        HOW_TO_FIX
    }
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.secret_scanning_default.to_outcome()
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.secret_scanning.to_outcome()
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let org_off = ctx
        .org
        .map(|o| !matches!(o.secret_scanning_default, FeatureDefaultState::Enabled));
    feature_state_phrase("secret scanning", ctx.repos, |r| r.secret_scanning, org_off)
}
