use super::context::{BranchEval, BranchProtectionState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "immutable";
pub const DESCRIPTION: &str = "release branches disallow force pushes and deletions (Settings → Branches → ruleset → Block force pushes, Restrict deletions)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
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
