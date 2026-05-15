use crate::checks::StateCtx;
use crate::checks::common::{FeatureState, feature_state_phrase};
use crate::checks::org_context::{FeatureDefaultState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories secret push protection is enabled";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/security_products > Advanced Security > (__Click__ -> Set up or __Edit__ -> Existing one) > __Click__ -> Custom configuration > Push protection > __Select__ -> Enabled > __Click__ -> Save/Update configuration > __Click__ -> Pencil to edit configuration > Edit configuration > __Select__ -> Apply to: All repositories > __Select__ -> Default for new repositories: All > __Click__ -> Review > __Click__ -> Save and enable";
pub const WHY_ENABLE: &str = "Scanning finds secrets after they reach GitHub; push protection rejects them at the git layer so the credential never enters history, forks, mirrors, or backups in the first place.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.push_protection_default.to_outcome("n/a (plan)")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.push_protection.to_outcome()
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let org_off = ctx
        .org
        .map(|o| !matches!(o.push_protection_default, FeatureDefaultState::Enabled));
    feature_state_phrase(
        "secret push protection",
        ctx.repos,
        |r| matches!(r.push_protection, FeatureState::Disabled),
        org_off,
    )
}
