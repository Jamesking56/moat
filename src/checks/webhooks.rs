use crate::checks::repo_context::{RepoContext, WebhooksState};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "webhooks";
pub const HOW_TO_FIX: &str = "github → repository → settings → webhooks → edit each webhook → set \"Payload URL\" to an `https://` endpoint, set a \"Secret\", and verify signatures on the receiver.";
pub const WHY_ENABLE: &str = "plain-http hooks leak payloads (and any secrets inside them) to any network on the path, and a hook without a shared secret has no way to prove the request actually came from github.";

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
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
