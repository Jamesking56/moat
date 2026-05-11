use crate::support::github::{Client, Fetch};
use crate::support::outcome::CheckOutcome;
use anyhow::Result;
use serde::Deserialize;

pub struct RepoContext {
    pub name: String,
    pub archived: bool,
    pub branch_protection: BranchProtectionState,
    pub workflow_token: WorkflowTokenState,
    pub secret_scanning: FeatureState,
    pub push_protection: FeatureState,
    pub dependabot_alerts: FeatureState,
}

pub enum BranchProtectionState {
    Protected { signed_commits: bool, pr_reviews: bool },
    Unprotected,
    NoDefaultBranch,
    NoPermission,
}

impl BranchProtectionState {
    pub fn flag_outcome(&self, flag: impl FnOnce(bool, bool) -> bool) -> CheckOutcome {
        match self {
            BranchProtectionState::Protected { signed_commits, pr_reviews } => {
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
    required_pull_request_reviews: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct EnabledFlag {
    enabled: bool,
}

#[derive(Deserialize)]
struct WorkflowPerms {
    default_workflow_permissions: String,
}

impl RepoContext {
    pub async fn fetch(client: &Client, org: &str, repo: RepoListing) -> Result<Self> {
        if repo.fork {
            return Ok(Self {
                name: repo.name,
                archived: repo.archived,
                branch_protection: BranchProtectionState::NoDefaultBranch,
                workflow_token: WorkflowTokenState::NoPermission,
                secret_scanning: FeatureState::Unknown,
                push_protection: FeatureState::Unknown,
                dependabot_alerts: FeatureState::Unknown,
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
                    },
                    Fetch::NotFound => BranchProtectionState::Unprotected,
                    Fetch::Forbidden => BranchProtectionState::NoPermission,
                }
            }
        };

        let workflow_token = match client
            .get_json::<WorkflowPerms>(&format!("/repos/{org}/{}/actions/permissions/workflow", repo.name))
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

        Ok(Self {
            name: repo.name,
            archived: repo.archived,
            branch_protection,
            workflow_token,
            secret_scanning,
            push_protection,
            dependabot_alerts,
        })
    }
}

fn pick_feature(repo: &RepoListing, pick: impl Fn(&SecurityAndAnalysis) -> &Option<FeatureStatus>) -> FeatureState {
    let Some(sa) = &repo.security_and_analysis else {
        return FeatureState::Unknown;
    };
    match pick(sa) {
        Some(f) if f.status == "enabled" => FeatureState::Enabled,
        Some(_) => FeatureState::Disabled,
        None => FeatureState::Unknown,
    }
}
