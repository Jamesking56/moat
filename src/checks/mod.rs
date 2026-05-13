pub mod common;
pub mod org_context;
pub mod repo_context;

pub mod admin_enforcement;
pub mod default_repo_permission;
pub mod dependabot_alerts;
pub mod dependabot_config;
pub mod direct_collaborators;
pub mod fork_pr_contributor_approval;
pub mod immutable_branch;
pub mod linear_history;
pub mod members_without_2fa;
pub mod pinned_actions;
pub mod pr_reviews;
pub mod private_vulnerability_reporting;
pub mod protected_release_branches;
pub mod pull_request_target;
pub mod push_protection;
pub mod release_immutability;
pub mod secret_scanning;
pub mod security_md;
pub mod signed_commits;
pub mod two_factor_required;
pub mod webhooks;
pub mod workflow_permissions;
pub mod workflow_token;

pub use org_context::OrgContext;
pub use repo_context::RepoContext;

use crate::support::outcome::CheckOutcome;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    Org,
    Repo,
    OrgAndRepo,
}

pub struct Check {
    pub id: &'static str,
    pub label: &'static str,
    pub how_to_fix: &'static str,
    pub why_enable: &'static str,
    pub org_eval: Option<fn(&OrgContext) -> CheckOutcome>,
    pub repo_eval: Option<fn(&RepoContext) -> CheckOutcome>,
}

impl Check {
    pub fn scope(&self) -> Scope {
        match (self.org_eval.is_some(), self.repo_eval.is_some()) {
            (true, true) => Scope::OrgAndRepo,
            (true, false) => Scope::Org,
            (false, true) => Scope::Repo,
            (false, false) => panic!("check `{}` has no evaluators", self.id),
        }
    }
}

pub static CHECKS: &[Check] = &[
    // ----- Org-only -----
    Check {
        id: "two_factor_required",
        label: two_factor_required::LABEL,
        how_to_fix: two_factor_required::HOW_TO_FIX,
        why_enable: two_factor_required::WHY_ENABLE,
        org_eval: Some(two_factor_required::org_check),
        repo_eval: None,
    },
    Check {
        id: "members_without_2fa",
        label: members_without_2fa::LABEL,
        how_to_fix: members_without_2fa::HOW_TO_FIX,
        why_enable: members_without_2fa::WHY_ENABLE,
        org_eval: Some(members_without_2fa::org_check),
        repo_eval: None,
    },
    Check {
        id: "default_repo_permission",
        label: default_repo_permission::LABEL,
        how_to_fix: default_repo_permission::HOW_TO_FIX,
        why_enable: default_repo_permission::WHY_ENABLE,
        org_eval: Some(default_repo_permission::org_check),
        repo_eval: None,
    },
    Check {
        id: "release_immutability",
        label: release_immutability::LABEL,
        how_to_fix: release_immutability::HOW_TO_FIX,
        why_enable: release_immutability::WHY_ENABLE,
        org_eval: Some(release_immutability::org_check),
        repo_eval: None,
    },
    Check {
        id: "fork_pr_contributor_approval",
        label: fork_pr_contributor_approval::LABEL,
        how_to_fix: fork_pr_contributor_approval::HOW_TO_FIX,
        why_enable: fork_pr_contributor_approval::WHY_ENABLE,
        org_eval: Some(fork_pr_contributor_approval::org_check),
        repo_eval: None,
    },
    // ----- Org + Repo (merged) -----
    Check {
        id: "workflow_token",
        label: workflow_token::LABEL,
        how_to_fix: workflow_token::HOW_TO_FIX,
        why_enable: workflow_token::WHY_ENABLE,
        org_eval: Some(workflow_token::org_check),
        repo_eval: Some(workflow_token::repo_check),
    },
    Check {
        id: "secret_scanning",
        label: secret_scanning::LABEL,
        how_to_fix: secret_scanning::HOW_TO_FIX,
        why_enable: secret_scanning::WHY_ENABLE,
        org_eval: Some(secret_scanning::org_check),
        repo_eval: Some(secret_scanning::repo_check),
    },
    Check {
        id: "push_protection",
        label: push_protection::LABEL,
        how_to_fix: push_protection::HOW_TO_FIX,
        why_enable: push_protection::WHY_ENABLE,
        org_eval: Some(push_protection::org_check),
        repo_eval: Some(push_protection::repo_check),
    },
    Check {
        id: "dependabot_alerts",
        label: dependabot_alerts::LABEL,
        how_to_fix: dependabot_alerts::HOW_TO_FIX,
        why_enable: dependabot_alerts::WHY_ENABLE,
        org_eval: Some(dependabot_alerts::org_check),
        repo_eval: Some(dependabot_alerts::repo_check),
    },
    // ----- Repo-only -----
    Check {
        id: "protected_release_branches",
        label: protected_release_branches::LABEL,
        how_to_fix: protected_release_branches::HOW_TO_FIX,
        why_enable: protected_release_branches::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(protected_release_branches::repo_check),
    },
    Check {
        id: "signed_commits",
        label: signed_commits::LABEL,
        how_to_fix: signed_commits::HOW_TO_FIX,
        why_enable: signed_commits::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(signed_commits::repo_check),
    },
    Check {
        id: "pr_reviews",
        label: pr_reviews::LABEL,
        how_to_fix: pr_reviews::HOW_TO_FIX,
        why_enable: pr_reviews::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(pr_reviews::repo_check),
    },
    Check {
        id: "admin_enforcement",
        label: admin_enforcement::LABEL,
        how_to_fix: admin_enforcement::HOW_TO_FIX,
        why_enable: admin_enforcement::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(admin_enforcement::repo_check),
    },
    Check {
        id: "immutable_branch",
        label: immutable_branch::LABEL,
        how_to_fix: immutable_branch::HOW_TO_FIX,
        why_enable: immutable_branch::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(immutable_branch::repo_check),
    },
    Check {
        id: "linear_history",
        label: linear_history::LABEL,
        how_to_fix: linear_history::HOW_TO_FIX,
        why_enable: linear_history::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(linear_history::repo_check),
    },
    Check {
        id: "pinned_actions",
        label: pinned_actions::LABEL,
        how_to_fix: pinned_actions::HOW_TO_FIX,
        why_enable: pinned_actions::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(pinned_actions::repo_check),
    },
    Check {
        id: "pull_request_target",
        label: pull_request_target::LABEL,
        how_to_fix: pull_request_target::HOW_TO_FIX,
        why_enable: pull_request_target::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(pull_request_target::repo_check),
    },
    Check {
        id: "workflow_permissions",
        label: workflow_permissions::LABEL,
        how_to_fix: workflow_permissions::HOW_TO_FIX,
        why_enable: workflow_permissions::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(workflow_permissions::repo_check),
    },
    Check {
        id: "webhooks",
        label: webhooks::LABEL,
        how_to_fix: webhooks::HOW_TO_FIX,
        why_enable: webhooks::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(webhooks::repo_check),
    },
    Check {
        id: "direct_collaborators",
        label: direct_collaborators::LABEL,
        how_to_fix: direct_collaborators::HOW_TO_FIX,
        why_enable: direct_collaborators::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(direct_collaborators::repo_check),
    },
    Check {
        id: "security_md",
        label: security_md::LABEL,
        how_to_fix: security_md::HOW_TO_FIX,
        why_enable: security_md::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(security_md::repo_check),
    },
    Check {
        id: "private_vulnerability_reporting",
        label: private_vulnerability_reporting::LABEL,
        how_to_fix: private_vulnerability_reporting::HOW_TO_FIX,
        why_enable: private_vulnerability_reporting::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(private_vulnerability_reporting::repo_check),
    },
    Check {
        id: "dependabot_config",
        label: dependabot_config::LABEL,
        how_to_fix: dependabot_config::HOW_TO_FIX,
        why_enable: dependabot_config::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(dependabot_config::repo_check),
    },
];
