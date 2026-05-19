use crate::checks::StateCtx;
use crate::checks::common::{noun, repos_word};
use crate::checks::repo_context::{RepoContext, SHAPinningState};
use crate::support::outcome::CheckOutcome;
use crate::support::workflows;

pub const LABEL: &str = "Repositories workflow actions are pinned";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/actions > General actions permissions > *Check* -> Require actions to be pinned to a full-length commit SHA > *Click* -> Save\n\nThen, in each affected workflow file below, replace every tag or branch ref with the full-length commit SHA (keep the tag as a trailing comment for readability). For example:\n```diff\n    - name: Cache dependencies\n-      uses: actions/cache@v5\n+      uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5\n```\nTip: hand the file list to your coding agent and ask it to pin every `uses:` ref — it can resolve each tag to its commit SHA for you.";
pub const WHY_ENABLE: &str = "Tags and branches are mutable — when tj-actions/changed-files was compromised in 2025, the attacker repointed the existing tags, so every workflow `@v1` instantly ran malicious code; SHA pins make that impossible, and the repo-level \"Require actions to be pinned\" setting prevents anyone from re-introducing unpinned refs. Note: enforcement happens at workflow run time — a push with unpinned `uses:` refs is not rejected, but any workflow it triggers will fail to start until the refs are pinned.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    let enforced = matches!(ctx.sha_pinning, SHAPinningState::Enforced);
    let not_enforced = matches!(ctx.sha_pinning, SHAPinningState::NotEnforced);

    let multi = ctx.workflows.len() > 1;
    let mut unpinned: Vec<String> = Vec::new();
    let mut failing_branches: Vec<String> = Vec::new();
    let has_workflows = ctx.workflows.has_any_workflows();

    for (branch, wfs) in ctx.workflows.iter() {
        let mut branch_unpinned: Vec<String> = Vec::new();
        for wf in wfs {
            for uses in workflows::collect_uses(&wf.doc) {
                if !workflows::is_pinned(&uses) {
                    branch_unpinned.push(format!("unpinned ref — {}: {}", wf.path, uses));
                }
            }
        }
        if !branch_unpinned.is_empty() && !failing_branches.contains(branch) {
            failing_branches.push(branch.clone());
        }
        for f in branch_unpinned {
            unpinned.push(if multi { format!("{branch}: {f}") } else { f });
        }
    }

    if !has_workflows {
        return CheckOutcome::skipped_no_data("N/A (no workflows)", "repos, no workflows");
    }

    if enforced && unpinned.is_empty() {
        return CheckOutcome::pass("✓");
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

        let mut outcome = CheckOutcome::fail("✗").with_items(items);
        if !failing_branches.is_empty() {
            outcome = outcome.with_failing_branches(failing_branches);
        }
        return outcome;
    }

    CheckOutcome::pass("✓")
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let mut total_unpinned = 0usize;
    let mut bad_repos = 0usize;
    let mut applicable = 0usize;
    let mut enforced_repos = 0usize;
    let mut not_enforced_repos = 0usize;
    for r in ctx.repos {
        let enforced = matches!(r.sha_pinning, SHAPinningState::Enforced);
        let not_enforced = matches!(r.sha_pinning, SHAPinningState::NotEnforced);
        let has_workflows = r.workflows.has_any_workflows();

        if !has_workflows {
            continue;
        }

        applicable += 1;
        if enforced {
            enforced_repos += 1;
        }
        if not_enforced {
            not_enforced_repos += 1;
        }

        let mut repo_unpinned = 0usize;
        for (_, wfs) in r.workflows.iter() {
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
                "every workflow action is SHA-pinned across all {applicable} {} with workflows",
                repos_word(applicable)
            )
        }
    } else if total_unpinned == 0 {
        format!(
            "{not_enforced_repos}/{applicable} {} don't enforce SHA pinning at the repo level",
            repos_word(applicable)
        )
    } else if not_enforced_repos > 0 {
        format!(
            "{total_unpinned} unpinned {} across {bad_repos}/{applicable} {} with workflows ({not_enforced_repos} also don't enforce it at the repo level)",
            noun(total_unpinned, "action reference", "action references"),
            repos_word(applicable)
        )
    } else {
        format!(
            "{total_unpinned} unpinned {} across {bad_repos}/{applicable} {} with workflows",
            noun(total_unpinned, "action reference", "action references"),
            repos_word(applicable)
        )
    })
}
