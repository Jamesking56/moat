use super::context::{OrgContext, WorkflowTokenState};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "github actions workflow token";
pub const DESCRIPTION: &str = "org default GITHUB_TOKEN permission for Actions is read-only (Settings → Actions → General → Workflow permissions)";
pub const HOW_TO_FIX: &str =
    "github → organization → settings → actions → general → workflow permissions → read repository contents and packages permissions";
pub const WHY_ENABLE: &str =
    "every workflow inherits this token by default; granting write at the org level means a typo'd action reference or a hijacked third-party action can rewrite history, tags, and releases without ever needing a maintainer's credentials.";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.workflow_token {
        WorkflowTokenState::Read => CheckOutcome::pass("read-only"),
        WorkflowTokenState::Write => CheckOutcome::fail("read and write"),
        WorkflowTokenState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
