use crate::checks::StateCtx;
use crate::checks::common::public_repos_word;
use crate::checks::repo_context::{FilePresence, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories have security policy";
pub const HOW_TO_FIX: &str = "https://github.com/{org}/{repo}/security/policy > __Click__ -> Start setup > __Edit__ -> SECURITY.md (use a private disclosure channel: email or GitHub advisories) > __Click__ -> Commit changes";
pub const WHY_ENABLE: &str = "Without a disclosure channel, well-meaning researchers file public issues with full PoCs — `SECURITY.md` is what funnels them to a private channel before the world sees the bug.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.security_md {
        FilePresence::Present => CheckOutcome::pass("✓"),
        FilePresence::Absent => CheckOutcome::fail("✗"),
        FilePresence::Unknown => CheckOutcome::skipped("?"),
    }
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    if total == 0 {
        return None;
    }
    let missing = ctx
        .repos
        .iter()
        .filter(|r| matches!(r.security_md, FilePresence::Absent))
        .count();
    Some(if missing == 0 {
        format!(
            "all {total} {} publish a SECURITY.md disclosure policy",
            public_repos_word(total)
        )
    } else {
        format!(
            "{missing}/{total} {} have no SECURITY.md disclosure policy",
            public_repos_word(total)
        )
    })
}
