use super::context::{RepoContext, WorkflowTokenState};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "token";
pub const DESCRIPTION: &str = "default GITHUB_TOKEN permission for Actions is read-only (Settings → Actions → General → Workflow permissions)";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → actions → general → workflow permissions → read repository contents and packages permissions";
pub const WHY_ENABLE: &str =
    "the default `GITHUB_TOKEN` is handed to every workflow step; leaving it on write-all means a malicious or compromised action gets a write-capable repo token by default rather than having to ask for one.";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.workflow_token {
        WorkflowTokenState::Read => CheckOutcome::pass("read"),
        WorkflowTokenState::Write => CheckOutcome::fail("write"),
        WorkflowTokenState::NoPermission => CheckOutcome::skipped("?"),
    }
}
