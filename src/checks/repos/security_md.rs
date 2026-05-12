use super::context::{FilePresence, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "security";
pub const DESCRIPTION: &str = "SECURITY.md exists at the repo root, in .github/, or in docs/ (advertises a vulnerability-disclosure path)";
pub const HOW_TO_FIX: &str =
    "add a `SECURITY.md` at the repo root (or in `.github/`) — point it at a private disclosure channel (email or github advisories)";
pub const WHY_ENABLE: &str =
    "without a disclosure channel, well-meaning researchers file public issues with full PoCs — `SECURITY.md` is what funnels them to a private channel before the world sees the bug.";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.security_md {
        FilePresence::Present => CheckOutcome::pass("✓"),
        FilePresence::Absent => CheckOutcome::fail("✗"),
        FilePresence::Unknown => CheckOutcome::skipped("?"),
    }
}
