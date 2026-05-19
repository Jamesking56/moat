use crate::checks::StateCtx;
use crate::checks::common::{FilePresence, inspectable_branch_protection_repos, repos_word};
use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories pull requests require reviews";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/rules > (*Click* -> New ruleset -> New branch ruleset or *Edit* -> Existing one) > Enforcement status > *Select* -> Active > Target branches > *Add target* -> {branches} > Branch rules > *Check* -> Require a pull request before merging > Required approvals > *Set* -> 1 (or more) > *Check* -> Dismiss stale pull request approvals when new commits are pushed > *Check* -> Require approval of the most recent reviewable push > *Check* -> Require review from Code Owners > *Click* -> Create/Save changes";
pub const WHY_ENABLE: &str = "Without required reviews, a single compromised contributor account can push directly to a release branch — peer review is the cheapest mechanism that catches malicious patches before they ship. Stale-review dismissal and last-push approval close the gap where an attacker amends a previously-approved PR; code-owner review ensures changes to sensitive paths are seen by the right people.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if !ctx.rulesets.pull_request {
        return CheckOutcome::fail("Not required by any org-level ruleset");
    }
    let mut missing: Vec<&str> = Vec::new();
    if !ctx.rulesets.pr_dismiss_stale_reviews {
        missing.push("stale reviews not dismissed on new push");
    }
    if !ctx.rulesets.pr_require_last_push_approval {
        missing.push("last-push approval not required");
    }
    if !ctx.rulesets.pr_require_code_owner_review {
        missing.push("code-owner review not required");
    }
    if missing.is_empty() {
        CheckOutcome::pass("Required by an org-level ruleset")
    } else {
        CheckOutcome::fail(
            "Required by an org-level ruleset, but some sub-requirements are missing",
        )
        .with_items(missing.into_iter().map(String::from).collect())
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    let codeowners_present = matches!(ctx.codeowners, FilePresence::Present);
    ctx.branch_protections.aggregate(|state| match state {
        BranchProtectionState::Protected {
            pr_reviews,
            pr_dismiss_stale_reviews,
            pr_require_last_push_approval,
            pr_require_code_owner_review,
            ..
        } => {
            if !*pr_reviews {
                return BranchEval::Fail(vec!["reviews not required".into()]);
            }
            let mut reasons: Vec<String> = Vec::new();
            if !*pr_dismiss_stale_reviews {
                reasons.push("stale reviews not dismissed on new push".into());
            }
            if !*pr_require_last_push_approval {
                reasons.push("last-push approval not required".into());
            }
            if codeowners_present && !*pr_require_code_owner_review {
                reasons.push("code-owner review not required (CODEOWNERS present)".into());
            }
            if reasons.is_empty() {
                BranchEval::Pass
            } else {
                BranchEval::Fail(reasons)
            }
        }
        BranchProtectionState::Unprotected => BranchEval::Fail(Vec::new()),
        BranchProtectionState::PlanGated => BranchEval::PlanGated,
    })
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let org_fully_required = ctx.org.map(|o| {
        o.rulesets.pull_request
            && o.rulesets.pr_dismiss_stale_reviews
            && o.rulesets.pr_require_last_push_approval
            && o.rulesets.pr_require_code_owner_review
    });

    let total = inspectable_branch_protection_repos(ctx.repos);
    let missing = count_repos_missing_full_pr_reviews(ctx.repos);

    Some(match (org_fully_required, missing) {
        (Some(true), 0) if total > 0 => format!(
            "the full pull-request review policy (approval, stale dismissal, last-push approval, code-owner review) is required by an org-level ruleset and enforced on every release branch across all {total} {}",
            repos_word(total)
        ),
        (Some(true), n) => format!(
            "the full pull-request review policy is required by an org-level ruleset but not fully enforced on release branches in {n} {}",
            repos_word(n)
        ),
        (Some(false), 0) if total > 0 => format!(
            "no org-level ruleset requires the full pull-request review policy, though every release branch across {total} {} enforces it",
            repos_word(total)
        ),
        (Some(false), n) if n > 0 => format!(
            "no org-level ruleset requires the full pull-request review policy; {n} {} miss one or more sub-requirements (stale dismissal, last-push approval, or code-owner review when CODEOWNERS is present) on release branches",
            repos_word(n)
        ),
        (Some(false), _) => {
            "no org-level ruleset requires the full pull-request review policy".to_string()
        }
        (None, 0) if total > 0 => format!(
            "the full pull-request review policy is enforced on release branches across all {total} {}",
            repos_word(total)
        ),
        (None, n) if n > 0 => format!(
            "{n} {} miss one or more sub-requirements of the pull-request review policy (stale dismissal, last-push approval, or code-owner review when CODEOWNERS is present) on release branches",
            repos_word(n)
        ),
        _ => return None,
    })
}

fn count_repos_missing_full_pr_reviews(repos: &[&RepoContext]) -> usize {
    let mut count = 0;
    for r in repos {
        let codeowners_present = matches!(r.codeowners, FilePresence::Present);
        let mut any_fail = false;
        for (_, state) in &r.branch_protections.branches {
            let fails = match state {
                BranchProtectionState::Protected {
                    pr_reviews,
                    pr_dismiss_stale_reviews,
                    pr_require_last_push_approval,
                    pr_require_code_owner_review,
                    ..
                } => {
                    !*pr_reviews
                        || !*pr_dismiss_stale_reviews
                        || !*pr_require_last_push_approval
                        || (codeowners_present && !*pr_require_code_owner_review)
                }
                BranchProtectionState::Unprotected => true,
                BranchProtectionState::PlanGated => false,
            };
            if fails {
                any_fail = true;
                break;
            }
        }
        if any_fail {
            count += 1;
        }
    }
    count
}
