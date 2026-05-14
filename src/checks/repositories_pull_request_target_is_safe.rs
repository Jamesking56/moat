use crate::checks::StateCtx;
use crate::checks::common::{noun, public_repos_word as repos_word};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, WorkflowsState};

pub const LABEL: &str = "Repositories pull request target is safe";
pub const HOW_TO_FIX: &str = "Switch the trigger to `pull_request`, or ensure the workflow does not check out `github.event.pull_request.head.ref` (only check out the base ref).";
pub const WHY_ENABLE: &str = "`pull_request_target` runs with the base repo's secrets and write token; if the workflow then checks out the PR's code, any fork PR executes attacker-controlled code with full repo privileges.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    let workflows = match &ctx.workflows {
        WorkflowsState::Loaded(w) if w.is_empty() => return CheckOutcome::skipped("N/a"),
        WorkflowsState::Loaded(w) => w,
        WorkflowsState::NoPermission => return CheckOutcome::skipped("?"),
    };

    let mut bad: Vec<String> = Vec::new();
    for wf in workflows {
        if workflows::has_pull_request_target(&wf.doc) && workflows::has_untrusted_checkout(&wf.doc)
        {
            bad.push(wf.path.clone());
        }
    }

    if bad.is_empty() {
        CheckOutcome::pass("✓")
    } else {
        CheckOutcome::fail("✗").with_items(bad)
    }
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let mut total_bad = 0usize;
    let mut bad_repos = 0usize;
    let mut applicable = 0usize;
    for r in ctx.repos {
        if let WorkflowsState::Loaded(wfs) = &r.workflows {
            if wfs.is_empty() {
                continue;
            }
            applicable += 1;
            let mut repo_bad = 0usize;
            for wf in wfs {
                if workflows::has_pull_request_target(&wf.doc)
                    && workflows::has_untrusted_checkout(&wf.doc)
                {
                    repo_bad += 1;
                }
            }
            if repo_bad > 0 {
                bad_repos += 1;
                total_bad += repo_bad;
            }
        }
    }

    if applicable == 0 {
        return None;
    }
    Some(if total_bad == 0 {
        format!(
            "no workflow combines `pull_request_target` with an untrusted checkout across all {applicable} {} with workflows",
            repos_word(applicable)
        )
    } else {
        format!(
            "{total_bad} {} combine `pull_request_target` with an untrusted checkout across {bad_repos}/{applicable} {}",
            noun(total_bad, "workflow", "workflows"),
            repos_word(applicable)
        )
    })
}
