use crate::config::Config;
use crate::support::github::{Client, Fetch, Fetch403};
use crate::support::outcome::CheckOutcome;
use crate::support::panel;
use crate::support::workflows::{self, WorkflowsState};
use anyhow::Result;
use futures::future::try_join_all;
use serde::Deserialize;

async fn traced<F, T>(repo: &str, label: &str, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let out = fut.await;
    panel::progress(&format!("{repo}: {label}"));
    out
}

pub struct RepoContext {
    pub name: String,
    pub archived: bool,
    pub private: bool,
    pub default_branch: Option<String>,
    pub branch_protections: BranchProtections,
    pub workflow_token: WorkflowTokenState,
    pub secret_scanning: FeatureState,
    pub push_protection: FeatureState,
    pub dependabot_alerts: FeatureState,
    pub workflows: WorkflowsState,
    pub security_md: FilePresence,
    pub dependabot_config: DependabotConfigState,
    pub webhooks: WebhooksState,
    pub direct_collaborators: DirectCollaboratorsState,
    pub config: Config,
}

pub enum BranchProtectionState {
    Protected {
        signed_commits: bool,
        pr_reviews: bool,
        enforce_admins: bool,
        required_linear_history: bool,
        allow_force_pushes: bool,
        allow_deletions: bool,
    },
    Unprotected,
    NoPermission,
    PlanGated,
}

#[derive(Default)]
pub struct BranchProtections {
    pub branches: Vec<(String, BranchProtectionState)>,
}

impl BranchProtections {
    pub fn from_single(name: impl Into<String>, state: BranchProtectionState) -> Self {
        Self {
            branches: vec![(name.into(), state)],
        }
    }

    pub fn none() -> Self {
        Self {
            branches: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.branches.is_empty()
    }

    pub fn any_plan_gated(&self) -> bool {
        self.branches
            .iter()
            .any(|(_, s)| matches!(s, BranchProtectionState::PlanGated))
    }

    /// Aggregate a per-branch evaluation across all release branches.
    /// `eval` returns Ok(()) for pass, Err(reasons) for fail (reasons are appended
    /// prefixed with the branch name when more than one branch is tracked).
    pub fn aggregate<F>(&self, eval: F) -> CheckOutcome
    where
        F: Fn(&BranchProtectionState) -> BranchEval,
    {
        if self.is_empty() {
            return CheckOutcome::skipped("—");
        }
        let multi = self.branches.len() > 1;
        let mut failures: Vec<String> = Vec::new();
        let mut failing_branches: Vec<String> = Vec::new();
        let mut any_unknown = false;
        let mut any_plan_gated = false;
        let mut any_pass = false;
        for (name, state) in &self.branches {
            match eval(state) {
                BranchEval::Pass => any_pass = true,
                BranchEval::Fail(reasons) => {
                    if !failing_branches.contains(name) {
                        failing_branches.push(name.clone());
                    }
                    if reasons.is_empty() {
                        failures.push(if multi {
                            format!("{name}: ✗")
                        } else {
                            "✗".into()
                        });
                    } else {
                        for r in reasons {
                            failures.push(if multi { format!("{name}: {r}") } else { r });
                        }
                    }
                }
                BranchEval::Unknown => any_unknown = true,
                BranchEval::PlanGated => any_plan_gated = true,
            }
        }
        if !failures.is_empty() {
            let summary = if multi {
                format!("✗ {}", failing_branches.join(", "))
            } else {
                "✗".to_string()
            };
            CheckOutcome::fail(summary).with_items(failures)
        } else if any_pass {
            CheckOutcome::pass("✓")
        } else if any_plan_gated {
            CheckOutcome::skipped("n/a (plan)")
        } else if any_unknown {
            CheckOutcome::skipped("?")
        } else {
            CheckOutcome::pass("✓")
        }
    }
}

pub enum BranchEval {
    Pass,
    Fail(Vec<String>),
    Unknown,
    PlanGated,
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
    PlanGated,
}

impl FeatureState {
    pub fn to_outcome(&self) -> CheckOutcome {
        match self {
            FeatureState::Enabled => CheckOutcome::pass("✓"),
            FeatureState::Disabled => CheckOutcome::fail("✗"),
            FeatureState::Unknown => CheckOutcome::skipped("?"),
            FeatureState::PlanGated => CheckOutcome::skipped("n/a (plan)"),
        }
    }
}

pub enum FilePresence {
    Present,
    Absent,
    Unknown,
}

pub enum DependabotConfigState {
    Ok { github_actions: bool },
    Missing,
    Unknown,
}

pub enum WebhooksState {
    Ok(Vec<WebhookInfo>),
    NoPermission,
}

pub enum DirectCollaboratorsState {
    Ok(Vec<String>),
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
    #[serde(default)]
    pub private: bool,
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
    required_pull_request_reviews: Option<serde::de::IgnoredAny>,
    enforce_admins: Option<EnabledFlag>,
    required_linear_history: Option<EnabledFlag>,
    allow_force_pushes: Option<EnabledFlag>,
    allow_deletions: Option<EnabledFlag>,
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
                private: repo.private,
                default_branch: repo.default_branch,
                branch_protections: BranchProtections::none(),
                workflow_token: WorkflowTokenState::NoPermission,
                secret_scanning: FeatureState::Unknown,
                push_protection: FeatureState::Unknown,
                dependabot_alerts: FeatureState::Unknown,
                workflows: WorkflowsState::Loaded(Vec::new()),
                security_md: FilePresence::Unknown,
                dependabot_config: DependabotConfigState::Unknown,
                webhooks: WebhooksState::NoPermission,
                direct_collaborators: DirectCollaboratorsState::NoPermission,
                config: Config::default(),
            });
        }

        // Phase 1: config + branch listing in parallel (branch protections need both).
        let (config, branch_entries) = tokio::try_join!(
            traced(&repo.name, "config", fetch_config(client, org, &repo.name)),
            traced(
                &repo.name,
                "branch listing",
                fetch_branch_entries(client, org, &repo.name),
            ),
        )?;

        let mut release_branch_names =
            compute_release_branches(&repo.default_branch, &config, branch_entries);
        release_branch_names.sort();

        // Phase 2: every remaining endpoint runs concurrently.
        let (
            branches,
            workflow_token,
            dependabot_alerts,
            workflows,
            security_md,
            dependabot_config,
            webhooks,
            direct_collaborators,
        ) = tokio::try_join!(
            traced(
                &repo.name,
                "branch protections",
                fetch_all_branch_protections(client, org, &repo.name, &release_branch_names),
            ),
            traced(
                &repo.name,
                "workflow token permissions",
                fetch_workflow_token(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "dependabot alerts",
                fetch_dependabot_alerts(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "workflows",
                workflows::fetch_workflows(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "SECURITY.md",
                locate_security_md(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "dependabot config",
                fetch_dependabot_config(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "webhooks",
                fetch_webhooks(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "direct collaborators",
                fetch_direct_collaborators(client, org, &repo.name, repo.private),
            ),
        )?;

        let branch_protections = BranchProtections { branches };

        let plan_gated = repo.private && branch_protections.any_plan_gated();
        let secret_scanning = pick_feature(&repo, |s| &s.secret_scanning, plan_gated);
        let push_protection =
            pick_feature(&repo, |s| &s.secret_scanning_push_protection, plan_gated);

        Ok(Self {
            name: repo.name,
            archived: repo.archived,
            private: repo.private,
            default_branch: repo.default_branch,
            branch_protections,
            workflow_token,
            secret_scanning,
            push_protection,
            dependabot_alerts,
            workflows,
            security_md,
            dependabot_config,
            webhooks,
            direct_collaborators,
            config,
        })
    }
}

async fn fetch_branch_protection(
    client: &Client,
    org: &str,
    repo: &str,
    branch: &str,
) -> Result<BranchProtectionState> {
    let path = format!("/repos/{org}/{repo}/branches/{branch}/protection");
    Ok(
        match client
            .get_json_plan_aware::<BranchProtection>(&path)
            .await?
        {
            Fetch403::Ok(bp) => BranchProtectionState::Protected {
                signed_commits: bp.required_signatures.map(|s| s.enabled).unwrap_or(false),
                pr_reviews: bp.required_pull_request_reviews.is_some(),
                enforce_admins: bp.enforce_admins.map(|e| e.enabled).unwrap_or(false),
                required_linear_history: bp
                    .required_linear_history
                    .map(|e| e.enabled)
                    .unwrap_or(false),
                allow_force_pushes: bp.allow_force_pushes.map(|e| e.enabled).unwrap_or(false),
                allow_deletions: bp.allow_deletions.map(|e| e.enabled).unwrap_or(false),
            },
            Fetch403::NotFound => BranchProtectionState::Unprotected,
            Fetch403::Forbidden => BranchProtectionState::NoPermission,
            Fetch403::PlanGated => BranchProtectionState::PlanGated,
        },
    )
}

#[derive(Deserialize)]
struct BranchEntry {
    name: String,
}

async fn fetch_branch_entries(client: &Client, org: &str, repo: &str) -> Result<Vec<BranchEntry>> {
    Ok(
        match client
            .get_paginated::<BranchEntry>(&format!("/repos/{org}/{repo}/branches"))
            .await?
        {
            Fetch::Ok(list) => list,
            Fetch::Forbidden | Fetch::NotFound => Vec::new(),
        },
    )
}

fn compute_release_branches(
    default_branch: &Option<String>,
    config: &Config,
    entries: Vec<BranchEntry>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Some(b) = default_branch
        && seen.insert(b.clone())
    {
        out.push(b.clone());
    }

    for b in config.release_branches() {
        if seen.insert(b.clone()) {
            out.push(b.clone());
        }
    }

    for entry in entries {
        if is_release_pattern(&entry.name) && seen.insert(entry.name.clone()) {
            out.push(entry.name);
        }
    }

    out
}

async fn fetch_all_branch_protections(
    client: &Client,
    org: &str,
    repo: &str,
    branches: &[String],
) -> Result<Vec<(String, BranchProtectionState)>> {
    try_join_all(branches.iter().map(|branch| async move {
        let state = fetch_branch_protection(client, org, repo, branch).await?;
        Ok::<_, anyhow::Error>((branch.clone(), state))
    }))
    .await
}

async fn fetch_workflow_token(
    client: &Client,
    org: &str,
    repo: &str,
) -> Result<WorkflowTokenState> {
    Ok(
        match client
            .get_json::<WorkflowPerms>(&format!("/repos/{org}/{repo}/actions/permissions/workflow"))
            .await?
        {
            Fetch::Ok(w) if w.default_workflow_permissions == "read" => WorkflowTokenState::Read,
            Fetch::Ok(_) => WorkflowTokenState::Write,
            _ => WorkflowTokenState::NoPermission,
        },
    )
}

async fn fetch_dependabot_alerts(client: &Client, org: &str, repo: &str) -> Result<FeatureState> {
    Ok(
        match client
            .get_presence(&format!("/repos/{org}/{repo}/vulnerability-alerts"))
            .await?
        {
            Fetch::Ok(_) => FeatureState::Enabled,
            Fetch::NotFound => FeatureState::Disabled,
            Fetch::Forbidden => FeatureState::Unknown,
        },
    )
}

fn is_release_pattern(name: &str) -> bool {
    let mut chars = name.chars();
    let mut had_digit = false;
    loop {
        match chars.next() {
            Some(c) if c.is_ascii_digit() => had_digit = true,
            Some('.') if had_digit => break,
            _ => return false,
        }
    }
    matches!(chars.next(), Some('x') | Some('X')) && chars.next().is_none()
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
    plan_gated: bool,
) -> FeatureState {
    let Some(sa) = &repo.security_and_analysis else {
        return if plan_gated {
            FeatureState::PlanGated
        } else {
            FeatureState::Unknown
        };
    };
    match pick(sa) {
        Some(f) if f.status == "enabled" => FeatureState::Enabled,
        Some(_) if plan_gated => FeatureState::PlanGated,
        Some(_) => FeatureState::Disabled,
        None if plan_gated => FeatureState::PlanGated,
        None => FeatureState::Unknown,
    }
}

async fn fetch_dependabot_config(
    client: &Client,
    org: &str,
    repo: &str,
) -> Result<DependabotConfigState> {
    for path in [".github/dependabot.yml", ".github/dependabot.yaml"] {
        match client
            .get_raw(&format!("/repos/{org}/{repo}/contents/{path}"))
            .await?
        {
            Fetch::Ok(text) => {
                let github_actions = parse_has_github_actions(&text);
                return Ok(DependabotConfigState::Ok { github_actions });
            }
            Fetch::Forbidden => return Ok(DependabotConfigState::Unknown),
            Fetch::NotFound => {}
        }
    }
    Ok(DependabotConfigState::Missing)
}

fn parse_has_github_actions(text: &str) -> bool {
    #[derive(Deserialize)]
    struct DependabotFile {
        #[serde(default)]
        updates: Vec<UpdateEntry>,
    }
    #[derive(Deserialize)]
    struct UpdateEntry {
        #[serde(rename = "package-ecosystem", default)]
        package_ecosystem: String,
    }
    serde_yaml::from_str::<DependabotFile>(text)
        .map(|f| {
            f.updates
                .iter()
                .any(|u| u.package_ecosystem == "github-actions")
        })
        .unwrap_or(false)
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

#[derive(Deserialize)]
struct CollaboratorEntry {
    login: String,
    #[serde(default)]
    permissions: CollaboratorPerms,
}

#[derive(Deserialize, Default)]
struct CollaboratorPerms {
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    maintain: bool,
    #[serde(default)]
    push: bool,
    #[serde(default)]
    triage: bool,
}

impl CollaboratorPerms {
    fn is_more_than_read(&self) -> bool {
        self.admin || self.maintain || self.push || self.triage
    }
}

async fn fetch_direct_collaborators(
    client: &Client,
    org: &str,
    repo: &str,
    private: bool,
) -> Result<DirectCollaboratorsState> {
    match client
        .get_paginated::<CollaboratorEntry>(&format!(
            "/repos/{org}/{repo}/collaborators?affiliation=direct"
        ))
        .await?
    {
        Fetch::Ok(v) => Ok(DirectCollaboratorsState::Ok(
            v.into_iter()
                .filter(|c| private || c.permissions.is_more_than_read())
                .map(|c| c.login)
                .collect(),
        )),
        Fetch::Forbidden | Fetch::NotFound => Ok(DirectCollaboratorsState::NoPermission),
    }
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
