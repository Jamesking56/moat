use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "secret push protection";
pub const HOW_TO_FIX: &str = "github → organization → settings → code security → configurations → enable push protection by default (and per-repo: settings → code security → push protection → enable).";
pub const WHY_ENABLE: &str = "scanning finds secrets after they reach github; push protection rejects them at the git layer so the credential never enters history, forks, mirrors, or backups in the first place.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.push_protection_default.to_outcome("n/a (plan)")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.push_protection.to_outcome()
}
