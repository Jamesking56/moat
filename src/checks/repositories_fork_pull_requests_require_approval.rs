use crate::checks::StateCtx;
use crate::checks::common::public_repos_word as repos_word;
use crate::checks::org_context::{ForkPrContributorApprovalState, OrgContext};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories fork pull requests require approval";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/actions > Approval for running fork pull request workflows from contributors > __Select__ -> Require approval for all external contributors > __Click__ -> Save";
pub const WHY_ENABLE: &str = "A fork PR can ship malicious workflow changes that run with your runners' filesystem and network access on the first push; approval gating lets a human read the diff before code from a stranger executes.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    evaluate(ctx.fork_pr_contributor_approval)
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    evaluate(ctx.fork_pr_contributor_approval)
}

fn evaluate(state: ForkPrContributorApprovalState) -> CheckOutcome {
    match state {
        ForkPrContributorApprovalState::AllExternalContributors => {
            CheckOutcome::pass("Required for all external contributors")
        }
        ForkPrContributorApprovalState::FirstTimeContributors => {
            CheckOutcome::fail("Required only for first-time contributors")
        }
        ForkPrContributorApprovalState::FirstTimeContributorsNewToGithub => {
            CheckOutcome::fail("Required only for first-time contributors new to GitHub")
        }
        ForkPrContributorApprovalState::Other => CheckOutcome::fail("Not enabled"),
        ForkPrContributorApprovalState::Unknown => CheckOutcome::skipped("Unknown"),
    }
}

fn is_full_approval(state: ForkPrContributorApprovalState) -> bool {
    matches!(
        state,
        ForkPrContributorApprovalState::AllExternalContributors
    )
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    let weak = ctx
        .repos
        .iter()
        .filter(|r| !is_full_approval(r.fork_pr_contributor_approval))
        .count();
    let org_full = ctx
        .org
        .map(|o| is_full_approval(o.fork_pr_contributor_approval));

    Some(match (org_full, weak) {
        (Some(true), 0) if total > 0 => format!(
            "fork PR workflows require manual approval for all external contributors across all {total} {}",
            repos_word(total)
        ),
        (Some(true), n) => format!(
            "fork PR approval is required org-wide for all external contributors, but {n}/{total} {} override it",
            repos_word(total)
        ),
        (Some(false), 0) if total > 0 => format!(
            "the org default does not require approval for every external contributor, though all {total} {} require it",
            repos_word(total)
        ),
        (Some(false), n) if n > 0 => format!(
            "the org default does not require approval for every external contributor; {n}/{total} {} run fork workflows without it",
            repos_word(total)
        ),
        (Some(false), _) => {
            "the org default does not require approval for every external contributor".into()
        }
        (None, 0) if total > 0 => format!(
            "fork PR workflows require manual approval for all external contributors across all {total} {}",
            repos_word(total)
        ),
        (None, n) if n > 0 => format!(
            "{n}/{total} {} run fork PR workflows without approval for every external contributor",
            repos_word(total)
        ),
        _ => return None,
    })
}
