use crate::support::github::{Fetch, GitHubClient};
use crate::support::outcome::CheckOutcome;
use crate::support::panel;
use anyhow::{Result, anyhow};
use serde::Deserialize;

pub(crate) async fn traced<F, T>(prefix: Option<&str>, label: &str, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let out = fut.await;
    match prefix {
        Some(p) => panel::progress(&format!("{p}: {label}")),
        None => panel::progress(label),
    }
    out
}

pub fn noun<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

pub fn repos_word(count: usize) -> &'static str {
    if count == 1 {
        "repository"
    } else {
        "repositories"
    }
}

pub fn public_repos_word(count: usize) -> &'static str {
    if count == 1 {
        "public repository"
    } else {
        "public repositories"
    }
}

/// Build an error for the case where moat hit a 403 / 404 it doesn't know how
/// to recover from. `NoPermission` and `Unknown` states are not supposed to
/// reach the evaluation layer — when they do, we bail out so the operator can
/// fix their token scopes (or report a missing handler).
pub fn permission_error(resource: &str, owner: &str, repo: Option<&str>) -> anyhow::Error {
    let target = match repo {
        Some(r) => format!("{owner}/{r}"),
        None => owner.to_string(),
    };
    anyhow!(
        "missing permission to read {resource} for `{target}` — check that your token has the required scopes (`admin:org`, `repo`, `workflow`) and that the account is an organization admin",
    )
}

/// Build a "currently:" phrase for a feature with both an org-default and a
/// per-repo toggle (e.g. secret scanning, push protection, dependabot alerts).
///
/// `feature` names the feature in user terms (e.g. "secret scanning").
/// `repo_state` returns the per-repo `FeatureState`. The denominator only
/// counts repos where the state is `Enabled` or `Disabled` — `PlanGated` maps
/// to a `Skipped` aggregate that the summary excludes too.
/// `org_off` returns true if the org default is *disabled* / not set.
pub fn feature_state_phrase(
    feature: &str,
    repos: &[&crate::checks::RepoContext],
    repo_state: impl Fn(&crate::checks::RepoContext) -> FeatureState,
    org_off: Option<bool>,
) -> Option<String> {
    let total = repos
        .iter()
        .filter(|r| {
            matches!(
                repo_state(r),
                FeatureState::Enabled | FeatureState::Disabled
            )
        })
        .count();
    let off = repos
        .iter()
        .filter(|r| matches!(repo_state(r), FeatureState::Disabled))
        .count();
    Some(match (org_off, off) {
        (Some(false), 0) if total > 0 => format!(
            "{feature} is enabled by default and on all {total} {}",
            repos_word(total)
        ),
        (Some(true), 0) if total > 0 => format!(
            "{feature} is not enabled by default for new repositories, but all {total} {} have it enabled",
            repos_word(total)
        ),
        (Some(false), n) => format!(
            "{feature} is enabled by default org-wide, but {n}/{total} {} override it",
            repos_word(total)
        ),
        (Some(true), n) if n > 0 => format!(
            "{feature} is not enabled by default; disabled on {n}/{total} {}",
            repos_word(total)
        ),
        (Some(true), _) => format!("{feature} is not enabled by default for new repositories"),
        (None, 0) if total > 0 => {
            format!("{feature} is enabled on all {total} {}", repos_word(total))
        }
        (None, n) if n > 0 => format!("{feature} is disabled on {n}/{total} {}", repos_word(total)),
        _ => return None,
    })
}

/// Number of repos with at least one release branch we could actually inspect
/// (state is `Protected` or `Unprotected`). Repos whose every release branch
/// came back `PlanGated` are excluded — they correspond to the `Skipped`
/// aggregates that the summary line subtracts from its denominator, so
/// descriptions sharing this denominator match the headline count.
pub fn inspectable_branch_protection_repos(repos: &[&crate::checks::RepoContext]) -> usize {
    use crate::checks::repo_context::BranchProtectionState;
    repos
        .iter()
        .filter(|r| {
            r.branch_protections.branches.iter().any(|(_, s)| {
                matches!(
                    s,
                    BranchProtectionState::Protected { .. } | BranchProtectionState::Unprotected
                )
            })
        })
        .count()
}

/// Build a "currently:" phrase for a ruleset-style requirement (e.g. signed
/// commits, linear history, required reviews) where the org enforces it via a
/// ruleset and each repo enforces it via branch protection on release branches.
pub fn ruleset_state_phrase<F>(
    feature: &str,
    repos: &[&crate::checks::RepoContext],
    pick: F,
    org_required: Option<bool>,
) -> Option<String>
where
    F: Fn(&crate::checks::repo_context::BranchProtectionState) -> Option<bool>,
{
    let total = inspectable_branch_protection_repos(repos);
    let missing = count_repos_missing_branch_flag(repos, pick);
    Some(match (org_required, missing) {
        (Some(true), 0) if total > 0 => format!(
            "{feature} is required by an org-level ruleset and enforced on every release branch across all {total} {}",
            repos_word(total)
        ),
        (Some(true), n) => format!(
            "{feature} is required by an org-level ruleset, but {n}/{total} {} override it on release branches",
            repos_word(total)
        ),
        (Some(false), 0) if total > 0 => format!(
            "{feature} is not required by any org-level ruleset, though every release branch across {total} {} enforces it",
            repos_word(total)
        ),
        (Some(false), n) if n > 0 => format!(
            "{feature} is not required by any org-level ruleset; {n}/{total} {} leave release branches unprotected",
            repos_word(total)
        ),
        (Some(false), _) => format!("{feature} is not required by any org-level ruleset"),
        (None, 0) if total > 0 => format!(
            "{feature} is enforced on release branches across all {total} {}",
            repos_word(total)
        ),
        (None, n) if n > 0 => format!(
            "{n}/{total} {} leave release branches unprotected from {feature}-related changes",
            repos_word(total)
        ),
        _ => return None,
    })
}

/// Count repos where the chosen branch-protection flag is missing (false or
/// branch unprotected). Branches we can't inspect (PlanGated) are skipped.
pub fn count_repos_missing_branch_flag<F>(repos: &[&crate::checks::RepoContext], pick: F) -> usize
where
    F: Fn(&crate::checks::repo_context::BranchProtectionState) -> Option<bool>,
{
    use crate::checks::repo_context::BranchProtectionState;
    let mut count = 0;
    for r in repos {
        let mut any_fail = false;
        for (_, state) in &r.branch_protections.branches {
            let fails = match pick(state) {
                Some(true) => false,
                Some(false) => true,
                None => matches!(state, BranchProtectionState::Unprotected),
            };
            if fails {
                any_fail = true;
                break;
            }
        }
        if any_fail {
            count += 1;
        }
    }
    count
}

#[derive(Clone, Copy)]
pub enum WorkflowTokenState {
    Read,
    Write,
}

#[derive(Clone, Copy)]
pub enum FeatureState {
    Enabled,
    Disabled,
    PlanGated,
}

impl FeatureState {
    pub fn to_outcome(&self) -> CheckOutcome {
        match self {
            FeatureState::Enabled => CheckOutcome::pass("✓"),
            FeatureState::Disabled => CheckOutcome::fail("✗"),
            FeatureState::PlanGated => CheckOutcome::skipped("N/A (plan)"),
        }
    }
}

pub enum FilePresence {
    Present,
    Absent,
}

#[derive(Clone)]
pub struct WebhookInfo {
    pub url: String,
    pub has_secret: bool,
}

#[derive(Deserialize)]
struct Webhook {
    config: WebhookConfig,
}

#[derive(Deserialize)]
struct WebhookConfig {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    secret: Option<String>,
}

pub(crate) async fn fetch_webhooks(
    client: &impl GitHubClient,
    path: &str,
    owner: &str,
    repo: Option<&str>,
) -> Result<Vec<WebhookInfo>> {
    match client.get_paginated::<Webhook>(path).await? {
        Fetch::Ok(v) => Ok(v
            .into_iter()
            .map(|h| WebhookInfo {
                url: h.config.url.unwrap_or_default(),
                has_secret: h.config.secret.is_some(),
            })
            .collect()),
        // Reading webhooks requires the `admin:org_hook` / `admin:repo_hook` scope, which is
        // narrower than `admin:org` / `repo`. If the token can't see this endpoint, skip the
        // check rather than failing the whole run.
        Fetch::Forbidden | Fetch::NotFound => {
            let _ = (owner, repo);
            Ok(Vec::new())
        }
    }
}

pub fn evaluate_webhooks(hooks: &[WebhookInfo]) -> CheckOutcome {
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

pub(crate) async fn locate_security_md(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
) -> Result<FilePresence> {
    for path in ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"] {
        match client
            .get_presence(&format!("/repos/{org}/{repo}/contents/{path}"))
            .await?
        {
            Fetch::Ok(_) => return Ok(FilePresence::Present),
            Fetch::Forbidden => return Err(permission_error("SECURITY.md", org, Some(repo))),
            Fetch::NotFound => {}
        }
    }
    Ok(FilePresence::Absent)
}

pub(crate) async fn locate_codeowners(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
) -> Result<FilePresence> {
    for path in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"] {
        match client
            .get_presence(&format!("/repos/{org}/{repo}/contents/{path}"))
            .await?
        {
            Fetch::Ok(_) => return Ok(FilePresence::Present),
            Fetch::Forbidden => return Err(permission_error("CODEOWNERS", org, Some(repo))),
            Fetch::NotFound => {}
        }
    }
    Ok(FilePresence::Absent)
}

#[derive(Deserialize)]
pub(crate) struct CollaboratorEntry {
    pub login: String,
    #[serde(default)]
    pub permissions: CollaboratorPerms,
}

#[derive(Deserialize, Default)]
pub(crate) struct CollaboratorPerms {
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub maintain: bool,
    #[serde(default)]
    pub push: bool,
    #[serde(default)]
    pub triage: bool,
}

impl CollaboratorPerms {
    pub fn is_more_than_read(&self) -> bool {
        self.admin || self.maintain || self.push || self.triage
    }
}
