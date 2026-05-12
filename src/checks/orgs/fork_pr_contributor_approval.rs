use super::context::{ForkPrContributorApprovalState, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "external contributor approval";
pub const DESCRIPTION: &str = "org requires manual approval before GitHub Actions workflows run on pull requests from all external contributors (Settings → Actions → General → Fork pull request workflows from outside collaborators)";

pub fn check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.fork_pr_contributor_approval {
        ForkPrContributorApprovalState::AllExternalContributors => {
            CheckOutcome::pass("required for all external contributors")
        }
        ForkPrContributorApprovalState::FirstTimeContributors => {
            CheckOutcome::fail("required only for first-time contributors")
        }
        ForkPrContributorApprovalState::FirstTimeContributorsNewToGithub => {
            CheckOutcome::fail("required only for first-time contributors new to GitHub")
        }
        ForkPrContributorApprovalState::Other => CheckOutcome::fail("NOT required"),
        ForkPrContributorApprovalState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
