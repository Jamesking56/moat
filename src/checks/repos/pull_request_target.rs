use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, WorkflowsState};

pub const COLUMN: &str = "pr-target";
pub const DESCRIPTION: &str = "no workflow combines the `pull_request_target` trigger with a checkout of an untrusted PR head ref (privilege-escalation footgun)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    let workflows = match &ctx.workflows {
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
