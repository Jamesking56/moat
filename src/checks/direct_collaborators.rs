use crate::checks::repo_context::{DirectCollaboratorsState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "direct collaborators";
pub const HOW_TO_FIX: &str = "github → repository → settings → collaborators and teams → under \"Manage access\", remove direct users → grant access via teams instead.";
pub const WHY_ENABLE: &str = "direct collaborators bypass org-level team membership audits and outlive role changes; access reviews miss them, so a long-departed contributor can keep push rights indefinitely.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    match &ctx.direct_collaborators {
        DirectCollaboratorsState::NoPermission => CheckOutcome::skipped("?"),
        DirectCollaboratorsState::Ok(v) if v.is_empty() => CheckOutcome::pass("✓"),
        DirectCollaboratorsState::Ok(v) => CheckOutcome::fail(v.len().to_string()),
    }
}
