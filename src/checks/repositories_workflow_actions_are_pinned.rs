use crate::checks::StateCtx;
use crate::checks::common::{noun, repos_word};
use crate::checks::repo_context::{RepoContext, SHAPinningState};
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, WorkflowsState};

pub const LABEL: &str = "Repositories workflow actions are pinned";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/actions > General actions permissions > __Check__ -> Require actions to be pinned to a full-length commit SHA > __Click__ -> Save";
pub const WHY_ENABLE: &str = "Tags and branches are mutable — when tj-actions/changed-files was compromised in 2025, the attacker repointed the existing tags, so every workflow `@v1` instantly ran malicious code; SHA pins make that impossible, and the repo-level \"Require actions to be pinned\" setting prevents anyone from re-introducing unpinned refs. Note: enforcement happens at workflow run time — a push with unpinned `uses:` refs is not rejected, but any workflow it triggers will fail to start until the refs are pinned.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    let enforced = matches!(ctx.sha_pinning, SHAPinningState::Enforced);
    let not_enforced = matches!(ctx.sha_pinning, SHAPinningState::NotEnforced);

    let mut unpinned: Vec<String> = Vec::new();
    let mut workflows_unknown = false;
    let mut has_workflows = false;
    match &ctx.workflows {
        WorkflowsState::Loaded(wfs) => {
            has_workflows = !wfs.is_empty();
            for wf in wfs {
                for uses in workflows::collect_uses(&wf.doc) {
                    if !workflows::is_pinned(&uses) {
                        unpinned.push(format!("unpinned ref — {}: {}", wf.path, uses));
                    }
                }
            }
        }
        WorkflowsState::NoPermission => workflows_unknown = true,
    }

    if enforced {
        return CheckOutcome::pass("✓ enforced via repo setting");
    }

    if not_enforced || !unpinned.is_empty() {
        let mut items: Vec<String> = Vec::new();
        if not_enforced {
            items.push(
                "repo setting \"Require actions to be pinned to a full-length commit SHA\" is OFF — settings → actions → general → Actions permissions"
                    .into(),
            );
        }
        items.extend(unpinned.iter().cloned());

        let summary = match (not_enforced, unpinned.len()) {
            (true, 0) if has_workflows => "✗ all pinned, but enforcement off".to_string(),
            (true, 0) => "✗ enforcement off".to_string(),
            (true, n) => format!("✗ {n} unpinned + enforcement off"),
            (false, n) => format!("✗ {n} unpinned"),
        };
        return CheckOutcome::fail(summary).with_items(items);
    }

    if workflows_unknown {
        return CheckOutcome::skipped("?");
    }
    if !has_workflows {
        return CheckOutcome::skipped("N/a (no workflows)");
    }
    CheckOutcome::pass("✓ all pinned (enforcement unknown)")
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let mut total_unpinned = 0usize;
    let mut bad_repos = 0usize;
    let mut applicable = 0usize;
    let mut enforced_repos = 0usize;
    let mut not_enforced_repos = 0usize;
    for r in ctx.repos {
        let enforced = matches!(r.sha_pinning, SHAPinningState::Enforced);
        let not_enforced = matches!(r.sha_pinning, SHAPinningState::NotEnforced);
        let has_workflows = matches!(&r.workflows, WorkflowsState::Loaded(w) if !w.is_empty());

        if !enforced && !not_enforced && !has_workflows {
            continue;
        }

        applicable += 1;
        if enforced {
            enforced_repos += 1;
            continue;
        }
        if not_enforced {
            not_enforced_repos += 1;
        }

        let mut repo_unpinned = 0usize;
        if let WorkflowsState::Loaded(wfs) = &r.workflows {
            for wf in wfs {
                for uses in workflows::collect_uses(&wf.doc) {
                    if !workflows::is_pinned(&uses) {
                        repo_unpinned += 1;
                    }
                }
            }
        }
        if repo_unpinned > 0 || not_enforced {
            bad_repos += 1;
            total_unpinned += repo_unpinned;
        }
    }

    if applicable == 0 {
        return None;
    }

    Some(if bad_repos == 0 {
        if enforced_repos == applicable {
            format!(
                "every {} enforces SHA pinning at the repo level",
                repos_word(applicable).trim_end_matches('s')
            )
        } else {
            format!(
                "every workflow action is SHA-pinned across all {applicable} {}",
                repos_word(applicable)
            )
        }
    } else if total_unpinned == 0 {
        format!(
            "{not_enforced_repos}/{applicable} {} don't enforce SHA pinning at the repo level",
            repos_word(applicable)
        )
    } else {
        format!(
            "{total_unpinned} unpinned {} across {bad_repos}/{applicable} {} ({not_enforced_repos} also don't enforce it at the repo level)",
            noun(total_unpinned, "action reference", "action references"),
            repos_word(applicable)
        )
    })
}
