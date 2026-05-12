use super::context::{DirectCollaboratorsState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "collabs";
pub const DESCRIPTION: &str =
    "users with direct (non-team) collaborator access on the repository — prefer team-based access";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    match &ctx.direct_collaborators {
        DirectCollaboratorsState::NoPermission => CheckOutcome::skipped("?"),
        DirectCollaboratorsState::Ok(v) if v.is_empty() => CheckOutcome::pass("✓"),
        DirectCollaboratorsState::Ok(v) => CheckOutcome::fail(v.len().to_string()),
    }
}
