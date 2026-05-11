use super::context::{FilePresence, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "security";
pub const DESCRIPTION: &str = "SECURITY.md exists at the repo root, in .github/, or in docs/ (advertises a vulnerability-disclosure path)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.security_md {
        FilePresence::Present => CheckOutcome::pass("✓"),
        FilePresence::Absent => CheckOutcome::fail("✗"),
        FilePresence::Unknown => CheckOutcome::skipped("?"),
    }
}
