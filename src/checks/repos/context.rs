use crate::config::Config;
use crate::support::github::{Client, Fetch};
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, WorkflowsState};
use anyhow::Result;
use serde::Deserialize;

pub struct RepoContext {
    pub name: String,
    pub archived: bool,
    pub default_branch: Option<String>,
    pub branch_protection: BranchProtectionState,
    pub workflow_token: WorkflowTokenState,
    pub secret_scanning: FeatureState,
    pub push_protection: FeatureState,
    pub dependabot_alerts: FeatureState,
    pub workflows: WorkflowsState,
    pub codeowners: FilePresence,
    pub security_md: FilePresence,
    pub webhooks: WebhooksState,
    pub config: Config,
}

pub enum BranchProtectionState {
    Protected {
        signed_commits: bool,
        pr_reviews: bool,
        enforce_admins: bool,
        require_code_owner_reviews: bool,
        required_linear_history: bool,
        allow_force_pushes: bool,
        allow_deletions: bool,
    },
    Unprotected,
    NoDefaultBranch,
    NoPermission,
}

impl BranchProtectionState {
    pub fn flag_outcome(&self, flag: impl FnOnce(bool, bool) -> bool) -> CheckOutcome {
        match self {
            BranchProtectionState::Protected {
                signed_commits,
                pr_reviews,
                ..
            } => {
                if flag(*signed_commits, *pr_reviews) {
                    CheckOutcome::pass("✓")
                } else {
                    CheckOutcome::fail("✗")
                }
            }
            BranchProtectionState::Unprotected => CheckOutcome::fail("✗"),
            BranchProtectionState::NoDefaultBranch | BranchProtectionState::NoPermission => {
                CheckOutcome::skipped("?")
            }
        }
    }
}

pub enum WorkflowTokenState {
    Read,
    Write,
    NoPermission,
}

pub enum FeatureState {
    Enabled,
    Disabled,
    Unknown,
}

impl FeatureState {
    pub fn to_outcome(&self) -> CheckOutcome {
        match self {
            FeatureState::Enabled => CheckOutcome::pass("✓"),
            FeatureState::Disabled => CheckOutcome::fail("✗"),
            FeatureState::Unknown => CheckOutcome::skipped("?"),
        }
    }
}

pub enum FilePresence {
    Present,
    Absent,
    Unknown,
}

pub enum WebhooksState {
    Ok(Vec<WebhookInfo>),
    NoPermission,
}

#[derive(Clone)]
pub struct WebhookInfo {
    pub url: String,
    pub has_secret: bool,
}

#[derive(Deserialize, Clone)]
pub struct RepoListing {
    pub name: String,
    pub archived: bool,
    pub fork: bool,
    pub default_branch: Option<String>,
    pub security_and_analysis: Option<SecurityAndAnalysis>,
}

#[derive(Deserialize, Clone)]
pub struct SecurityAndAnalysis {
    pub secret_scanning: Option<FeatureStatus>,
    pub secret_scanning_push_protection: Option<FeatureStatus>,
}

#[derive(Deserialize, Clone)]
pub struct FeatureStatus {
    pub status: String,
}

#[derive(Deserialize)]
struct BranchProtection {
    required_signatures: Option<EnabledFlag>,
    required_pull_request_reviews: Option<PrReviews>,
    enforce_admins: Option<EnabledFlag>,
    required_linear_history: Option<EnabledFlag>,
    allow_force_pushes: Option<EnabledFlag>,
    allow_deletions: Option<EnabledFlag>,
}

#[derive(Deserialize)]
struct PrReviews {
    #[serde(default)]
    require_code_owner_reviews: bool,
}

#[derive(Deserialize)]
struct EnabledFlag {
    enabled: bool,
}

#[derive(Deserialize)]
struct WorkflowPerms {
    default_workflow_permissions: String,
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

impl RepoContext {
    pub async fn fetch(client: &Client, org: &str, repo: RepoListing) -> Result<Self> {
        if repo.fork {
            return Ok(Self {
                name: repo.name,
                archived: repo.archived,
                default_branch: repo.default_branch,
                branch_protection: BranchProtectionState::NoDefaultBranch,
                workflow_token: WorkflowTokenState::NoPermission,
                secret_scanning: FeatureState::Unknown,
                push_protection: FeatureState::Unknown,
                dependabot_alerts: FeatureState::Unknown,
                workflows: WorkflowsState::Loaded(Vec::new()),
                codeowners: FilePresence::Unknown,
                security_md: FilePresence::Unknown,
                webhooks: WebhooksState::NoPermission,
                config: Config::default(),
            });
        }

        let branch_protection = match &repo.default_branch {
            None => BranchProtectionState::NoDefaultBranch,
            Some(branch) => {
                let path = format!("/repos/{org}/{}/branches/{}/protection", repo.name, branch);
                match client.get_json::<BranchProtection>(&path).await? {
                    Fetch::Ok(bp) => BranchProtectionState::Protected {
                        signed_commits: bp.required_signatures.map(|s| s.enabled).unwrap_or(false),
                        pr_reviews: bp.required_pull_request_reviews.is_some(),
                        enforce_admins: bp.enforce_admins.map(|e| e.enabled).unwrap_or(false),
                        require_code_owner_reviews: bp
                            .required_pull_request_reviews
                            .as_ref()
                            .map(|r| r.require_code_owner_reviews)
                            .unwrap_or(false),
                        required_linear_history: bp
                            .required_linear_history
                            .map(|e| e.enabled)
                            .unwrap_or(false),
                        allow_force_pushes: bp
                            .allow_force_pushes
                            .map(|e| e.enabled)
                            .unwrap_or(false),
                        allow_deletions: bp.allow_deletions.map(|e| e.enabled).unwrap_or(false),
                    },
                    Fetch::NotFound => BranchProtectionState::Unprotected,
                    Fetch::Forbidden => BranchProtectionState::NoPermission,
                }
            }
        };

        let workflow_token = match client
            .get_json::<WorkflowPerms>(&format!(
                "/repos/{org}/{}/actions/permissions/workflow",
                repo.name
            ))
            .await?
        {
            Fetch::Ok(w) if w.default_workflow_permissions == "read" => WorkflowTokenState::Read,
            Fetch::Ok(_) => WorkflowTokenState::Write,
            _ => WorkflowTokenState::NoPermission,
        };

        let secret_scanning = pick_feature(&repo, |s| &s.secret_scanning);
        let push_protection = pick_feature(&repo, |s| &s.secret_scanning_push_protection);

        let dependabot_alerts = match client
            .get_presence(&format!("/repos/{org}/{}/vulnerability-alerts", repo.name))
            .await?
        {
            Fetch::Ok(_) => FeatureState::Enabled,
            Fetch::NotFound => FeatureState::Disabled,
            Fetch::Forbidden => FeatureState::Unknown,
        };

        let workflows = workflows::fetch_workflows(client, org, &repo.name).await?;
        let codeowners = locate_codeowners(client, org, &repo.name).await?;
        let security_md = locate_security_md(client, org, &repo.name).await?;
        let webhooks = fetch_webhooks(client, org, &repo.name).await?;
        let config = fetch_config(client, org, &repo.name).await?;

        Ok(Self {
            name: repo.name,
            archived: repo.archived,
            default_branch: repo.default_branch,
            branch_protection,
            workflow_token,
            secret_scanning,
            push_protection,
            dependabot_alerts,
            workflows,
            codeowners,
            security_md,
            webhooks,
            config,
        })
    }
}

async fn fetch_config(client: &Client, org: &str, repo: &str) -> Result<Config> {
    match client
        .get_raw(&format!(
            "/repos/{org}/{repo}/contents/{}",
            crate::config::FILE_NAME
        ))
        .await?
    {
        Fetch::Ok(text) => Config::parse(&text),
        Fetch::NotFound | Fetch::Forbidden => Ok(Config::default()),
    }
}

fn pick_feature(
    repo: &RepoListing,
    pick: impl Fn(&SecurityAndAnalysis) -> &Option<FeatureStatus>,
) -> FeatureState {
    let Some(sa) = &repo.security_and_analysis else {
        return FeatureState::Unknown;
    };
    match pick(sa) {
        Some(f) if f.status == "enabled" => FeatureState::Enabled,
        Some(_) => FeatureState::Disabled,
        None => FeatureState::Unknown,
    }
}

async fn locate_codeowners(client: &Client, org: &str, repo: &str) -> Result<FilePresence> {
    for path in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"] {
        match client
            .get_presence(&format!("/repos/{org}/{repo}/contents/{path}"))
            .await?
        {
            Fetch::Ok(_) => return Ok(FilePresence::Present),
            Fetch::Forbidden => return Ok(FilePresence::Unknown),
            Fetch::NotFound => {}
        }
    }
    Ok(FilePresence::Absent)
}

async fn locate_security_md(client: &Client, org: &str, repo: &str) -> Result<FilePresence> {
    for path in ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"] {
        match client
            .get_presence(&format!("/repos/{org}/{repo}/contents/{path}"))
            .await?
        {
            Fetch::Ok(_) => return Ok(FilePresence::Present),
            Fetch::Forbidden => return Ok(FilePresence::Unknown),
            Fetch::NotFound => {}
        }
    }
    Ok(FilePresence::Absent)
}

async fn fetch_webhooks(client: &Client, org: &str, repo: &str) -> Result<WebhooksState> {
    match client
        .get_paginated::<Webhook>(&format!("/repos/{org}/{repo}/hooks"))
        .await?
    {
        Fetch::Ok(v) => Ok(WebhooksState::Ok(
            v.into_iter()
                .map(|h| WebhookInfo {
                    url: h.config.url.unwrap_or_default(),
                    has_secret: h.config.secret.is_some(),
                })
                .collect(),
        )),
        Fetch::Forbidden | Fetch::NotFound => Ok(WebhooksState::NoPermission),
    }
}
