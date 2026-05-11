use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, WorkflowsState};

pub const COLUMN: &str = "pinned";
pub const DESCRIPTION: &str = "every `uses:` in .github/workflows/*.yml is pinned to a 40-char commit SHA (mitigates the tj-actions/changed-files 2025 supply-chain compromise)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    let workflows = match &ctx.workflows {
        WorkflowsState::Loaded(w) => w,
        WorkflowsState::NoPermission => return CheckOutcome::skipped("?"),
    };

    let mut unpinned: Vec<String> = Vec::new();
    for wf in workflows {
        for uses in workflows::collect_uses(&wf.doc) {
            if !workflows::is_pinned(&uses) {
                unpinned.push(format!("{}: {}", wf.path, uses));
            }
        }
    }

    if unpinned.is_empty() {
        CheckOutcome::pass("✓")
    } else {
        CheckOutcome::fail(format!("{} unpinned", unpinned.len())).with_items(unpinned)
    }
}
