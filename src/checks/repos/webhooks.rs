use super::context::{RepoContext, WebhooksState};
use crate::support::outcome::CheckOutcome;

pub const COLUMN: &str = "hooks";
pub const DESCRIPTION: &str = "every repository webhook uses HTTPS and has a secret configured (prevents tampering and replay)";

pub fn check(ctx: &RepoContext) -> CheckOutcome {
    let hooks = match &ctx.webhooks {
        WebhooksState::Ok(v) => v,
        WebhooksState::NoPermission => return CheckOutcome::skipped("?"),
    };

    if hooks.is_empty() {
        return CheckOutcome::pass("—");
    }

    let mut findings: Vec<String> = Vec::new();
    for h in hooks {
        let url = if h.url.is_empty() {
            "<unknown>"
        } else {
            h.url.as_str()
        };
        if !h.url.starts_with("https://") {
            findings.push(format!("{url}: not HTTPS"));
        }
        if !h.has_secret {
            findings.push(format!("{url}: no secret"));
        }
    }

    if findings.is_empty() {
        CheckOutcome::pass("✓")
    } else {
        CheckOutcome::fail("✗").with_items(findings)
    }
}
