use crate::checks::StateCtx;
use crate::checks::common::repos_word;
use crate::checks::repo_context::{DependabotConfigState, RepoContext};
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::WorkflowsState;

pub const LABEL: &str = "Repositories have dependabot config";
pub const HOW_TO_FIX: &str = "Add a `.github/dependabot.yml` enabling the `github-actions` ecosystem with the following content:\n```yaml\nversion: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n```";
pub const WHY_ENABLE: &str = "Pinning actions to SHAs is only safe if something keeps them up to date; without Dependabot the pins rot and either get bumped to a tag (defeating the pin) or stay stuck on a known-vulnerable revision.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    if let WorkflowsState::Loaded(w) = &ctx.workflows
        && w.is_empty()
    {
        return CheckOutcome::skipped("N/a");
    }

    match &ctx.dependabot_config {
        DependabotConfigState::Ok { github_actions } => {
            if *github_actions {
                CheckOutcome::pass("✓")
            } else {
                CheckOutcome::fail("No actions ecosystem")
            }
        }
        DependabotConfigState::Missing => CheckOutcome::fail("Missing"),
        DependabotConfigState::Unknown => CheckOutcome::skipped("?"),
    }
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let mut applicable = 0usize;
    let mut missing = 0usize;
    let mut without_actions = 0usize;
    for r in ctx.repos {
        if let WorkflowsState::Loaded(w) = &r.workflows
            && w.is_empty()
        {
            continue;
        }
        applicable += 1;
        match &r.dependabot_config {
            DependabotConfigState::Ok { github_actions } if !*github_actions => {
                without_actions += 1;
            }
            DependabotConfigState::Missing => missing += 1,
            _ => {}
        }
    }
    if applicable == 0 {
        return None;
    }
    let bad = missing + without_actions;
    Some(if bad == 0 {
        format!(
            "all {applicable} {} with workflows track action updates via dependabot",
            repos_word(applicable)
        )
    } else if missing > 0 && without_actions > 0 {
        format!(
            "{missing}/{applicable} {} lack a dependabot config and {without_actions} more do not track the github-actions ecosystem",
            repos_word(applicable)
        )
    } else if missing > 0 {
        format!(
            "{missing}/{applicable} {} lack a dependabot config",
            repos_word(applicable)
        )
    } else {
        format!(
            "{without_actions}/{applicable} {} do not track the github-actions ecosystem in dependabot",
            repos_word(applicable)
        )
    })
}
