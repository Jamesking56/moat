use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "push";
pub const DESCRIPTION: &str = "push protection blocks commits containing secrets (Settings → Code security → Push protection)";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → code security → push protection → enable";
pub const WHY_ENABLE: &str =
    "once a secret reaches the remote, the only safe response is rotation — push protection catches it at `git push` while it's still local and cheap to fix.";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    ctx.push_protection.to_outcome()
}
