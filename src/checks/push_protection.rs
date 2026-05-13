use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "secret push protection";
pub const HOW_TO_FIX: &str = "github → your organization → settings → advanced security → configurations → open the configuration that enables \"Push protection\" → under \"Policy\", set \"Use as default for newly created repositories\" to apply to your repositories → Save configuration (per-repo: either apply a configuration that enables it — org settings → advanced security → configurations → next to the configuration, click \"Apply to\" and select the repo — or open the repo directly: settings → advanced security → under \"Secret Protection\", enable \"Push protection\").";
pub const WHY_ENABLE: &str = "scanning finds secrets after they reach github; push protection rejects them at the git layer so the credential never enters history, forks, mirrors, or backups in the first place.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.push_protection_default.to_outcome("n/a (plan)")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.push_protection.to_outcome()
}
