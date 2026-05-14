use crate::checks::StateCtx;
use crate::checks::common::{WorkflowTokenState, repos_word};
use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories actions workflow token is read only";
pub const HOW_TO_FIX: &str = "GitHub → your organization → settings → actions → general → under \"Workflow permissions\", select \"Read repository contents and packages permissions\" (apply the same setting per-repo at repo → settings → actions → general → workflow permissions).";
pub const WHY_ENABLE: &str = "Every workflow inherits this token by default; granting write at the org or repo level means a typo'd action reference or a hijacked third-party action can rewrite history, tags, and releases without ever needing a maintainer's credentials.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.workflow_token {
        WorkflowTokenState::Read => CheckOutcome::pass("Read-only by default for new repositories"),
        WorkflowTokenState::Write => {
            CheckOutcome::fail("Read and write by default for new repositories")
        }
        WorkflowTokenState::Unavailable => CheckOutcome::skipped("Unknown"),
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.workflow_token {
        WorkflowTokenState::Read => CheckOutcome::pass("Read"),
        WorkflowTokenState::Write => CheckOutcome::fail("Write"),
        WorkflowTokenState::Unavailable => CheckOutcome::skipped("?"),
    }
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    let bad = ctx
        .repos
        .iter()
        .filter(|r| matches!(r.workflow_token, WorkflowTokenState::Write))
        .count();
    let org_write = ctx
        .org
        .map(|o| matches!(o.workflow_token, WorkflowTokenState::Write));

    Some(match (org_write, bad) {
        (Some(false), 0) if total > 0 => format!(
            "workflow tokens are read-only across all {total} {}",
            repos_word(total)
        ),
        (Some(true), 0) if total > 0 => format!(
            "the org default grants workflow tokens write access, but all {total} {} restrict them to read-only",
            repos_word(total)
        ),
        (Some(false), n) if n > 0 => format!(
            "{n}/{total} {} grant workflow tokens write access to repository contents",
            repos_word(total)
        ),
        (Some(true), n) if n > 0 => format!(
            "the org default grants write access and {n}/{total} {} grant workflow tokens write access",
            repos_word(total)
        ),
        (Some(true), _) => {
            "the org default grants workflow tokens write access to repository contents".into()
        }
        (None, 0) if total > 0 => format!(
            "workflow tokens are read-only across all {total} {}",
            repos_word(total)
        ),
        (None, n) if n > 0 => format!(
            "{n}/{total} {} grant workflow tokens write access to repository contents",
            repos_word(total)
        ),
        _ => return None,
    })
}
