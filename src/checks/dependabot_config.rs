use crate::checks::repo_context::{DependabotConfigState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "dependabot config";
pub const HOW_TO_FIX: &str = "add `.github/dependabot.yml` with `package-ecosystem: github-actions` (and any other ecosystems you ship).";
pub const WHY_ENABLE: &str = "pinning actions to SHAs is only safe if something keeps them up to date; without dependabot the pins rot and either get bumped to a tag (defeating the pin) or stay stuck on a known-vulnerable revision.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    match &ctx.dependabot_config {
        DependabotConfigState::Ok { github_actions } => {
            if *github_actions {
                CheckOutcome::pass("✓")
            } else {
                CheckOutcome::fail("no actions ecosystem")
            }
        }
        DependabotConfigState::Missing => CheckOutcome::fail("missing"),
        DependabotConfigState::Unknown => CheckOutcome::skipped("?"),
    }
}
