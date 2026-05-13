use crate::checks::StateCtx;
use crate::checks::common::{noun, repos_word};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, WorkflowsState};

pub const LABEL: &str = "pinned actions";
pub const HOW_TO_FIX: &str = "in every workflow file, replace `uses: org/action@v1` with `uses: org/action@<40-char-SHA>  # v1` — let dependabot keep them current.";
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

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let mut total_unpinned = 0usize;
    let mut bad_repos = 0usize;
    let mut applicable = 0usize;
    for r in ctx.repos {
        if let WorkflowsState::Loaded(wfs) = &r.workflows {
            if wfs.is_empty() {
                continue;
            }
            applicable += 1;
            let mut repo_unpinned = 0usize;
            for wf in wfs {
                for uses in workflows::collect_uses(&wf.doc) {
                    if !workflows::is_pinned(&uses) {
                        repo_unpinned += 1;
                    }
                }
            }
            if repo_unpinned > 0 {
                bad_repos += 1;
                total_unpinned += repo_unpinned;
            }
        }
    }

    if applicable == 0 {
        return None;
    }
    Some(if total_unpinned == 0 {
        format!(
            "every workflow action is SHA-pinned across all {applicable} {} with workflows",
            repos_word(applicable)
        )
    } else {
        format!(
            "{total_unpinned} unpinned {} across {bad_repos}/{applicable} {}",
            noun(total_unpinned, "action reference", "action references"),
            repos_word(applicable)
        )
    })
}
