use super::context::{DependabotConfigState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "dependabot.yml";
pub const DESCRIPTION: &str = ".github/dependabot.yml exists and enables `package-ecosystem: github-actions` (keeps pinned action SHAs auto-updated)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
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
