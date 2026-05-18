use crate::checks::StateCtx;
use crate::checks::common::feature_state_phrase;
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories secret push protection is enabled";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/security_products > Advanced Security > (*Click* -> Set up or *Edit* -> Existing one) > *Click* -> Custom configuration > Push protection > *Select* -> Enabled > *Click* -> Save/Update configuration > *Click* -> Pencil to edit configuration > Edit configuration > *Select* -> Apply to: All repositories > *Select* -> Default for new repositories: All > *Click* -> Review > *Click* -> Save and enable";
pub const WHY_ENABLE: &str = "Scanning finds secrets after they reach GitHub; push protection rejects them at the git layer so the credential never enters history, forks, mirrors, or backups in the first place.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.push_protection_default.to_outcome()
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.push_protection.to_outcome()
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let org_off = ctx
        .org
        .map(|o| !matches!(o.push_protection_default, FeatureDefaultState::Enabled));
    feature_state_phrase(
        "secret push protection",
        ctx.repos,
        |r| r.push_protection,
        org_off,
    )
}
