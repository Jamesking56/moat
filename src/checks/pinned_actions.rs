use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, WorkflowsState};

pub const LABEL: &str = "pinned actions";
pub const HOW_TO_FIX: &str = "in every workflow file, replace `uses: org/action@v1` with `uses: org/action@<40-char-sha>  # v1` — let dependabot keep them current.";
pub const WHY_ENABLE: &str = "tags and branches are mutable — when tj-actions/changed-files was compromised in 2025 the attacker repointed the existing tags, so every workflow `@v1` instantly ran malicious code; SHA pins make that impossible.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    let workflows = match &ctx.workflows {
        WorkflowsState::Loaded(w) if w.is_empty() => return CheckOutcome::skipped("n/a"),
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
