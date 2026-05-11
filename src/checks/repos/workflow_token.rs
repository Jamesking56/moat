use super::context::{RepoContext, WorkflowTokenState};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "token";
pub const DESCRIPTION: &str =
    "default GITHUB_TOKEN permission for Actions is read-only (Settings → Actions → General → Workflow permissions)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.workflow_token {
        WorkflowTokenState::Read => CheckOutcome::pass("read"),
        WorkflowTokenState::Write => CheckOutcome::fail("write"),
        WorkflowTokenState::NoPermission => CheckOutcome::skipped("?"),
    }
}
