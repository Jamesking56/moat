use super::context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, WorkflowsState};

pub const COLUMN: &str = "pr-target";
pub const DESCRIPTION: &str = "no workflow combines the `pull_request_target` trigger with a checkout of an untrusted PR head ref (privilege-escalation footgun)";
pub const HOW_TO_FIX: &str =
    "switch the trigger to `pull_request`, or remove the `actions/checkout` of `github.event.pull_request.head.ref` and only check out the base ref";
pub const WHY_ENABLE: &str =
    "`pull_request_target` runs with the base repo's secrets and write token; if the workflow then checks out the PR's code, any fork PR executes attacker-controlled code with full repo privileges.";

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
