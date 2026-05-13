use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "secret push protection";
pub const HOW_TO_FIX: &str = "github → your organization → settings → advanced security → configurations → edit the default configuration → under \"Secret scanning\", set \"Push protection\" to \"Enabled\" (per-repo: repo → settings → advanced security → under \"Secret Protection\", enable \"Push protection\").";
pub const WHY_ENABLE: &str = "scanning finds secrets after they reach github; push protection rejects them at the git layer so the credential never enters history, forks, mirrors, or backups in the first place.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.push_protection_default.to_outcome("n/a (plan)")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.push_protection.to_outcome()
}
