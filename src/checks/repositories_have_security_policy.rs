use crate::checks::StateCtx;
use crate::checks::common::public_repos_word;
use crate::checks::repo_context::{FilePresence, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories have security policy";
pub const HOW_TO_FIX: &str = "In all the links below > *Click* -> Start setup > *Edit* -> SECURITY.md (use a private disclosure channel: email or GitHub advisories) > *Click* -> Commit changes with the following content:\n```markdown\n# Security Policy\n\n**PLEASE DON'T DISCLOSE SECURITY-RELATED ISSUES PUBLICLY, [SEE BELOW](#reporting-a-vulnerability).**\n\n## Reporting a Vulnerability\n\nIf you discover a security vulnerability, please report it privately using one of the following channels:\n\n1. **GitHub Private Vulnerability Reporting** (preferred) — go to the repository's **Security** tab and click **\"Report a vulnerability\"**. This creates a private advisory visible only to maintainers and provides a structured workflow for triage, fix coordination, and CVE assignment.\n\n2. **Email** — send the details to [YOUR NAME] at **your@email.com**.\n\nAll security vulnerabilities will be promptly addressed.\n```";
pub const WHY_ENABLE: &str = "Without a disclosure channel, well-meaning researchers file public issues with full PoCs — `SECURITY.md` is what funnels them to a private channel before the world sees the bug.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    match ctx.security_md {
        FilePresence::Present => CheckOutcome::pass("✓"),
        FilePresence::Absent => CheckOutcome::fail("✗"),
    }
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
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
            "{missing} {} have no SECURITY.md disclosure policy",
            public_repos_word(missing)
        )
    })
}
