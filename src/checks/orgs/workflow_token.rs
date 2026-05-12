use super::context::{OrgContext, WorkflowTokenState};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "workflow token";
pub const DESCRIPTION: &str = "org default GITHUB_TOKEN permission for Actions is read-only (Settings → Actions → General → Workflow permissions)";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.workflow_token {
        WorkflowTokenState::Read => CheckOutcome::pass("read"),
        WorkflowTokenState::Write => CheckOutcome::fail("write"),
        WorkflowTokenState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
