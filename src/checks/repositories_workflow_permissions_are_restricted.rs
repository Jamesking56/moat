use crate::checks::StateCtx;
use crate::checks::common::{noun, repos_word};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, PermissionsBlock, WorkflowsState};

pub const LABEL: &str = "repositories workflow permissions are restricted";
pub const HOW_TO_FIX: &str = "in each `.github/workflows/*.yml`, add a top-level `permissions:` block listing only the scopes the workflow actually needs (`contents: read`, etc.).";
pub const WHY_ENABLE: &str = "without a declared `permissions:` block (or with `write-all`), every step in the workflow — including third-party actions — runs with full repo write access, turning any compromised action into a code-push primitive.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    let workflows = match &ctx.workflows {
        WorkflowsState::Loaded(w) if w.is_empty() => return CheckOutcome::skipped("n/a"),
        WorkflowsState::Loaded(w) => w,
        WorkflowsState::NoPermission => return CheckOutcome::skipped("?"),
    };

    let mut findings: Vec<String> = Vec::new();
    for wf in workflows {
        match workflows::top_level_permissions(&wf.doc) {
            PermissionsBlock::Missing => {
                findings.push(format!("{}: missing permissions block", wf.path))
            }
            PermissionsBlock::WriteAll => findings.push(format!("{}: write-all", wf.path)),
            PermissionsBlock::Scoped(writes) if !writes.is_empty() => {
                findings.push(format!("{}: write scopes [{}]", wf.path, writes.join(", ")));
            }
            _ => {}
        }
        for (job, block) in workflows::job_level_permissions(&wf.doc) {
            match block {
                PermissionsBlock::WriteAll => {
                    findings.push(format!("{}: job `{}` write-all", wf.path, job));
                }
                PermissionsBlock::Scoped(writes) if !writes.is_empty() => {
                    findings.push(format!(
                        "{}: job `{}` write scopes [{}]",
                        wf.path,
                        job,
                        writes.join(", ")
                    ));
                }
                _ => {}
            }
        }
    }

    if findings.is_empty() {
        CheckOutcome::pass("✓")
    } else {
        CheckOutcome::fail("✗").with_items(findings)
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
                let top_bad = match workflows::top_level_permissions(&wf.doc) {
                    PermissionsBlock::Missing | PermissionsBlock::WriteAll => true,
                    PermissionsBlock::Scoped(w) if !w.is_empty() => true,
                    _ => false,
                };
                let job_bad =
                    workflows::job_level_permissions(&wf.doc)
                        .into_iter()
                        .any(|(_, b)| {
                            matches!(b, PermissionsBlock::WriteAll)
                                || matches!(b, PermissionsBlock::Scoped(w) if !w.is_empty())
                        });
                if top_bad || job_bad {
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
            "every workflow declares a read-only permissions block across all {applicable} {} with workflows",
            repos_word(applicable)
        )
    } else {
        format!(
            "{total_bad} {} grant write or omit the permissions block across {bad_repos}/{applicable} {}",
            noun(total_bad, "workflow", "workflows"),
            repos_word(applicable)
        )
    })
}
