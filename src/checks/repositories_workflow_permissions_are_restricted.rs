use crate::checks::StateCtx;
use crate::checks::common::{noun, repos_word};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, PermissionsBlock, Workflow};

pub const LABEL: &str = "Repositories workflow permissions are restricted";
pub const HOW_TO_FIX: &str = "In each `.github/workflows/*.yml` below > *Add* -> A top-level `permissions:` block > *Set* -> The minimum scopes needed — for read-only workflows:\n```yaml\npermissions:\n  contents: read\n```";
pub const WHY_ENABLE: &str = "Without a declared `permissions:` block (or with `write-all`), every step in the workflow — including third-party actions — runs with full repo write access, turning any compromised action into a code-push primitive.";

fn findings_for_workflows(wfs: &[Workflow]) -> Vec<String> {
    let mut findings: Vec<String> = Vec::new();
    for wf in wfs {
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
    findings
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    if ctx.workflows.is_empty() {
        return CheckOutcome::skipped("—");
    }
    if !ctx.workflows.has_any_workflows() {
        return CheckOutcome::skipped("N/A");
    }

    let multi = ctx.workflows.len() > 1;
    let mut all_findings: Vec<String> = Vec::new();
    let mut failing_branches: Vec<String> = Vec::new();
    for (branch, wfs) in ctx.workflows.iter() {
        let findings = findings_for_workflows(wfs);
        if findings.is_empty() {
            continue;
        }
        if !failing_branches.contains(branch) {
            failing_branches.push(branch.clone());
        }
        for f in findings {
            all_findings.push(if multi { format!("{branch}: {f}") } else { f });
        }
    }

    if !all_findings.is_empty() {
        return CheckOutcome::fail("✗")
            .with_items(all_findings)
            .with_failing_branches(failing_branches);
    }
    CheckOutcome::pass("✓")
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let mut total_bad = 0usize;
    let mut bad_repos = 0usize;
    let mut applicable = 0usize;
    for r in ctx.repos {
        if !r.workflows.has_any_workflows() {
            continue;
        }
        applicable += 1;
        let mut repo_bad = 0usize;
        for (_, wfs) in r.workflows.iter() {
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
        }
        if repo_bad > 0 {
            bad_repos += 1;
            total_bad += repo_bad;
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
            "{total_bad} {} grant write or omit the permissions block across {bad_repos}/{applicable} {} with workflows",
            noun(total_bad, "workflow", "workflows"),
            repos_word(applicable)
        )
    })
}
