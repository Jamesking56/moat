use super::context::{ForkPrContributorApprovalState, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const NAME: &str = "manual approval on github actions workflows";
pub const DESCRIPTION: &str = "org requires manual approval before GitHub Actions workflows run on pull requests from all external contributors (Settings → Actions → General → Fork pull request workflows from outside collaborators)";
pub const HOW_TO_FIX: &str =
    "github → organization → settings → actions → general → require approval for all external contributors";
pub const WHY_ENABLE: &str =
    "a fork PR can ship malicious workflow changes that run with your runners' filesystem and network access on the first push; approval gating lets a human read the diff before code from a stranger executes.";

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
        ForkPrContributorApprovalState::Other => CheckOutcome::fail("not enabled"),
        ForkPrContributorApprovalState::Unknown => CheckOutcome::skipped("unknown"),
    }
}
