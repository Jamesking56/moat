use crate::checks::common::WorkflowTokenState;
use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "github actions workflow token";
pub const HOW_TO_FIX: &str = "github → your organization → settings → actions → general → under \"Workflow permissions\", select \"Read repository contents and packages permissions\" (apply the same setting per-repo at repo → settings → actions → general → workflow permissions).";
pub const WHY_ENABLE: &str = "every workflow inherits this token by default; granting write at the org or repo level means a typo'd action reference or a hijacked third-party action can rewrite history, tags, and releases without ever needing a maintainer's credentials.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.workflow_token {
        WorkflowTokenState::Read => CheckOutcome::pass("read-only"),
        WorkflowTokenState::Write => CheckOutcome::fail("read and write"),
        WorkflowTokenState::Unavailable => CheckOutcome::skipped("unknown"),
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.workflow_token {
        WorkflowTokenState::Read => CheckOutcome::pass("read"),
        WorkflowTokenState::Write => CheckOutcome::fail("write"),
        WorkflowTokenState::Unavailable => CheckOutcome::skipped("?"),
    }
}
