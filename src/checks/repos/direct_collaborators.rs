use super::context::{DirectCollaboratorsState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "collabs";
pub const DESCRIPTION: &str =
    "users with direct (non-team) collaborator access on the repository — prefer team-based access";
pub const HOW_TO_FIX: &str =
    "github → repository → settings → collaborators → remove direct users → grant access via teams instead";
pub const WHY_ENABLE: &str =
    "direct collaborators bypass org-level team membership audits and outlive role changes; access reviews miss them, so a long-departed contributor can keep push rights indefinitely.";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    match &ctx.direct_collaborators {
        DirectCollaboratorsState::NoPermission => CheckOutcome::skipped("?"),
        DirectCollaboratorsState::Ok(v) if v.is_empty() => CheckOutcome::pass("✓"),
        DirectCollaboratorsState::Ok(v) => CheckOutcome::fail(v.len().to_string()),
    }
}
