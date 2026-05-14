use crate::checks::StateCtx;
use crate::checks::common::repos_word;
use crate::checks::org_context::{OrgContext, RulesetsState};
use crate::checks::repo_context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories default branch is locked";
pub const HOW_TO_FIX: &str = "GitHub → organization (or repository) → settings → rules → edit the ruleset for your release branches → under \"Rules\", enable both \"Block force pushes\" and \"Restrict deletions\".";
pub const WHY_ENABLE: &str = "Force pushes and branch deletions rewrite history — an attacker (or a tired maintainer) can erase the audit trail of a malicious commit or quietly replace a tagged release with a different tree.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.rulesets.state == RulesetsState::NoPermission {
        return CheckOutcome::skipped("?");
    }
    let mut missing: Vec<String> = Vec::new();
    if !ctx.rulesets.non_fast_forward {
        missing.push("force pushes allowed".into());
    }
    if !ctx.rulesets.deletion {
        missing.push("deletions allowed".into());
    }
    if missing.is_empty() {
        CheckOutcome::pass("Force pushes and deletions blocked by an org-level ruleset")
    } else {
        CheckOutcome::fail("Not fully locked at the org level").with_items(missing)
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    ctx.branch_protections.aggregate(|state| match state {
        BranchProtectionState::Protected {
            allow_force_pushes,
            allow_deletions,
            ..
        } => {
            let mut bad = Vec::new();
            if *allow_force_pushes {
                bad.push("force pushes allowed".into());
            }
            if *allow_deletions {
                bad.push("deletions allowed".into());
            }
            if bad.is_empty() {
                BranchEval::Pass
            } else {
                BranchEval::Fail(bad)
            }
        }
        BranchProtectionState::Unprotected => BranchEval::Fail(Vec::new()),
        BranchProtectionState::NoPermission => BranchEval::Unknown,
        BranchProtectionState::PlanGated => BranchEval::PlanGated,
    })
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    let bad = ctx
        .repos
        .iter()
        .filter(|r| {
            r.branch_protections.branches.iter().any(|(_, s)| match s {
                BranchProtectionState::Protected {
                    allow_force_pushes,
                    allow_deletions,
                    ..
                } => *allow_force_pushes || *allow_deletions,
                BranchProtectionState::Unprotected => true,
                _ => false,
            })
        })
        .count();

    let org_state = ctx.org.and_then(|o| {
        if o.rulesets.state == RulesetsState::NoPermission {
            return None;
        }
        let mut missing: Vec<&str> = Vec::new();
        if !o.rulesets.non_fast_forward {
            missing.push("force pushes");
        }
        if !o.rulesets.deletion {
            missing.push("deletions");
        }
        Some(missing)
    });

    Some(match (org_state, bad) {
        (Some(missing), 0) if missing.is_empty() && total > 0 => format!(
            "force pushes and deletions are blocked by an org-level ruleset and on every release branch across all {total} {}",
            repos_word(total)
        ),
        (Some(missing), n) if missing.is_empty() => format!(
            "org-level ruleset blocks force pushes and deletions, but {n}/{total} {} leave release branches unlocked",
            repos_word(total)
        ),
        (Some(missing), 0) if total > 0 => format!(
            "no org-level ruleset blocks {}, though every release branch across {total} {} is locked",
            missing.join(" or "),
            repos_word(total)
        ),
        (Some(missing), n) if n > 0 => format!(
            "no org-level ruleset blocks {}; {n}/{total} {} leave release branches unlocked",
            missing.join(" or "),
            repos_word(total)
        ),
        (Some(missing), _) => format!("no org-level ruleset blocks {}", missing.join(" or ")),
        (None, 0) if total > 0 => format!(
            "release branches are locked against force pushes and deletions across all {total} {}",
            repos_word(total)
        ),
        (None, n) if n > 0 => format!(
            "{n}/{total} {} leave release branches unlocked against force pushes or deletions",
            repos_word(total)
        ),
        _ => return None,
    })
}
