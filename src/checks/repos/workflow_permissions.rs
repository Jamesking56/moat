use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, PermissionsBlock, WorkflowsState};

pub const COLUMN: &str = "perms";
pub const DESCRIPTION: &str = "every workflow declares a top-level `permissions:` block that is not write-all (per-workflow least privilege)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    let workflows = match &ctx.workflows {
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
    }

    if findings.is_empty() {
        CheckOutcome::pass("✓")
    } else {
        CheckOutcome::fail("✗").with_items(findings)
    }
}
