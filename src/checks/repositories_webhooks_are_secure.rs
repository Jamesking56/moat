use crate::checks::StateCtx;
use crate::checks::common::{WebhookInfo, evaluate_webhooks, noun, repos_word};
use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories webhooks are secure";
pub const HOW_TO_FIX: &str = "https://github.com/{org}/{repo}/settings/hooks > *Edit* -> Each webhook > Payload URL > *Set* -> https:// endpoint > Secret > *Set* -> A secret token > *Click* -> Update webhook";
pub const WHY_ENABLE: &str = "Plain-HTTP hooks leak payloads (and any secrets inside them) to any network on the path, and a hook without a shared secret has no way to prove the request actually came from GitHub.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.webhooks.is_empty() {
        return CheckOutcome::pass("No organization webhooks configured");
    }
    let mut findings: Vec<String> = Vec::new();
    for h in &ctx.webhooks {
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
        CheckOutcome::pass("All organization webhooks use HTTPS and have a secret")
    } else {
        CheckOutcome::fail("One or more organization webhooks are insecure").with_items(findings)
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    evaluate_webhooks(&ctx.webhooks)
}

fn count_insecure(hooks: &[WebhookInfo]) -> usize {
    hooks
        .iter()
        .filter(|h| !h.url.starts_with("https://") || !h.has_secret)
        .count()
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    let mut bad_repos = 0usize;
    let mut repo_hook_total = 0usize;
    let mut repo_insecure = 0usize;
    for r in ctx.repos {
        repo_hook_total += r.webhooks.len();
        let bad = count_insecure(&r.webhooks);
        repo_insecure += bad;
        if bad > 0 {
            bad_repos += 1;
        }
    }

    let org_summary = ctx
        .org
        .map(|o| (o.webhooks.len(), count_insecure(&o.webhooks)));

    let org_phrase: Option<String> = org_summary.map(|(t, bad)| {
        if t == 0 {
            "no organization webhooks are configured".into()
        } else if bad == 0 {
            format!(
                "all {t} organization {} use HTTPS with a secret",
                noun(t, "webhook", "webhooks")
            )
        } else {
            format!(
                "{bad}/{t} organization {} lack HTTPS or a secret",
                noun(t, "webhook", "webhooks")
            )
        }
    });

    let repo_phrase: Option<String> = if total == 0 {
        None
    } else if repo_hook_total == 0 {
        Some(format!(
            "no repository webhooks across {total} {}",
            repos_word(total)
        ))
    } else if repo_insecure == 0 {
        Some(format!(
            "all {repo_hook_total} repository {} use HTTPS with a secret",
            noun(repo_hook_total, "webhook", "webhooks")
        ))
    } else {
        Some(format!(
            "{repo_insecure} repository {} across {bad_repos} {} lack HTTPS or a secret",
            noun(repo_insecure, "webhook", "webhooks"),
            repos_word(bad_repos)
        ))
    };

    match (org_phrase, repo_phrase) {
        (Some(o), Some(r)) => Some(format!("{o}; {r}")),
        (Some(o), None) => Some(o),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    }
}
