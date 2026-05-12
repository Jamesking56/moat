use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "secret scanning";
pub const HOW_TO_FIX: &str = "github → organization → settings → code security → configurations → enable secret scanning by default (and per-repo: settings → code security → secret scanning → enable).";
pub const WHY_ENABLE: &str = "secrets accidentally committed stay valid until someone notices; scanning gives you minutes-to-hours warning instead of waiting for a leaked-credential abuse alert from a downstream provider.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.secret_scanning_default.to_outcome("n/a (plan)")
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.secret_scanning.to_outcome()
}
