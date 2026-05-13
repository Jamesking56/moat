use crate::checks::repo_context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "immutable branches";
pub const HOW_TO_FIX: &str = "github → repository → settings → rules → edit the ruleset for your release branches → under \"Rules\", enable both \"Block force pushes\" and \"Restrict deletions\".";
pub const WHY_ENABLE: &str = "force pushes and branch deletions rewrite history — an attacker (or a tired maintainer) can erase the audit trail of a malicious commit or quietly replace a tagged release with a different tree.";

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
