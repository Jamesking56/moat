use moat::checks::common::WebhookInfo;
use moat::checks::org_context::{
    DefaultRepoPermissionState, FeatureDefaultState, ForkPrContributorApprovalState, OrgContext,
    OrgPlan, OrgRulesets, ReleaseImmutabilityState, TwoFactorState, WorkflowTokenState,
};
use moat::checks::{
    organization_members_all_have_two_factor as members_without_2fa,
    organization_new_members_default_to_no_permissions as default_repo_permission,
    organization_requires_two_factor as two_factor_required,
    repositories_branch_protection_applies_to_admins as admin_enforcement,
    repositories_dependabot_security_updates_are_enabled as dependabot_security_updates,
    repositories_fork_pull_requests_require_approval as fork_pr_approval,
    repositories_private_vulnerability_reporting_is_enabled as pvr,
    repositories_pull_requests_require_reviews as pr_reviews_org,
    repositories_release_branches_are_locked as immutable_branch,
    repositories_release_branches_have_linear_history as linear_history,
    repositories_releases_are_immutable as releases_immutable,
    repositories_webhooks_are_secure as webhooks_secure,
};
use moat::support::github::FakeGitHubClient;
use moat::support::outcome::Status;
use serde_json::json;

fn ctx(
    tfa: TwoFactorState,
    without: Vec<String>,
    outside: Vec<String>,
    admins: Vec<String>,
) -> OrgContext {
    OrgContext {
        plan: OrgPlan::Team,
        two_factor_required: tfa,
        members_without_2fa: without,
        outside_collaborators: outside,
        admins,
        default_repository_permission: DefaultRepoPermissionState::Read,
        release_immutability: ReleaseImmutabilityState::All,
        fork_pr_contributor_approval: ForkPrContributorApprovalState::AllExternalContributors,
        workflow_token: WorkflowTokenState::Read,
        secret_scanning_default: FeatureDefaultState::Enabled,
        push_protection_default: FeatureDefaultState::Enabled,
        dependabot_alerts_default: FeatureDefaultState::Enabled,
        dependabot_security_updates_default: FeatureDefaultState::Enabled,
        webhooks: Vec::new(),
        private_vulnerability_reporting: FeatureDefaultState::Enabled,
        rulesets: OrgRulesets::empty(),
    }
}

#[test]
fn two_factor_required_passes_when_required() {
    let c = ctx(TwoFactorState::Required, vec![], vec![], vec![]);
    let o = two_factor_required::org_check(&c);
    assert_eq!(o.status, Status::Pass);
    assert_eq!(o.summary, "Required for every member");
}

#[test]
fn two_factor_required_fails_when_not_required() {
    let c = ctx(TwoFactorState::NotRequired, vec![], vec![], vec![]);
    assert_eq!(two_factor_required::org_check(&c).status, Status::Fail);
}

#[test]
fn members_without_2fa_passes_when_empty() {
    let c = ctx(TwoFactorState::Required, vec![], vec![], vec![]);
    assert_eq!(members_without_2fa::org_check(&c).status, Status::Pass);
}

#[test]
fn members_without_2fa_fails_with_items_when_present() {
    let c = ctx(
        TwoFactorState::Required,
        vec!["alice".into(), "bob".into()],
        vec![],
        vec![],
    );
    let o = members_without_2fa::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.summary.to_ascii_lowercase().contains('2'));
    assert_eq!(o.items, vec!["alice", "bob"]);
}

fn base_ctx() -> OrgContext {
    ctx(TwoFactorState::Required, vec![], vec![], vec![])
}

#[test]
fn default_repo_permission_states() {
    let mut c = base_ctx();
    c.default_repository_permission = DefaultRepoPermissionState::None;
    assert_eq!(default_repo_permission::org_check(&c).status, Status::Pass);
    c.default_repository_permission = DefaultRepoPermissionState::Read;
    assert_eq!(default_repo_permission::org_check(&c).status, Status::Pass);
    c.default_repository_permission = DefaultRepoPermissionState::Write;
    assert_eq!(default_repo_permission::org_check(&c).status, Status::Fail);
    c.default_repository_permission = DefaultRepoPermissionState::Admin;
    assert_eq!(default_repo_permission::org_check(&c).status, Status::Fail);
    c.default_repository_permission = DefaultRepoPermissionState::Other("custom".into());
    assert_eq!(default_repo_permission::org_check(&c).status, Status::Warn);
}

#[test]
fn releases_immutable_org_states() {
    let mut c = base_ctx();
    c.release_immutability = ReleaseImmutabilityState::All;
    assert_eq!(releases_immutable::org_check(&c).status, Status::Pass);
    c.release_immutability = ReleaseImmutabilityState::Selected;
    assert_eq!(releases_immutable::org_check(&c).status, Status::Warn);
    c.release_immutability = ReleaseImmutabilityState::None;
    assert_eq!(releases_immutable::org_check(&c).status, Status::Fail);
}

#[test]
fn fork_pr_approval_org_states() {
    let mut c = base_ctx();
    c.fork_pr_contributor_approval = ForkPrContributorApprovalState::AllExternalContributors;
    assert_eq!(fork_pr_approval::org_check(&c).status, Status::Pass);
    c.fork_pr_contributor_approval = ForkPrContributorApprovalState::FirstTimeContributors;
    assert_eq!(fork_pr_approval::org_check(&c).status, Status::Fail);
    c.fork_pr_contributor_approval = ForkPrContributorApprovalState::Other;
    assert_eq!(fork_pr_approval::org_check(&c).status, Status::Fail);
}

#[test]
fn pvr_org_states() {
    let mut c = base_ctx();
    c.private_vulnerability_reporting = FeatureDefaultState::Enabled;
    assert_eq!(pvr::org_check(&c).status, Status::Pass);
    c.private_vulnerability_reporting = FeatureDefaultState::Disabled;
    assert_eq!(pvr::org_check(&c).status, Status::Fail);
    c.private_vulnerability_reporting = FeatureDefaultState::NotSet;
    assert_eq!(pvr::org_check(&c).status, Status::Warn);
}

#[test]
fn webhooks_org_empty_passes() {
    let mut c = base_ctx();
    c.webhooks = Vec::new();
    assert_eq!(webhooks_secure::org_check(&c).status, Status::Pass);
}

#[test]
fn webhooks_org_insecure_fails_with_findings() {
    let mut c = base_ctx();
    c.webhooks = vec![
        WebhookInfo {
            url: "http://a/h".into(),
            has_secret: true,
        },
        WebhookInfo {
            url: "https://b/h".into(),
            has_secret: false,
        },
    ];
    let o = webhooks_secure::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert_eq!(o.items.len(), 2);
}

fn rulesets(
    any_active: bool,
    required_linear_history: bool,
    non_fast_forward: bool,
    deletion: bool,
    has_bypass_actors: bool,
) -> OrgRulesets {
    OrgRulesets {
        any_active,
        required_signatures: false,
        pull_request: false,
        pr_dismiss_stale_reviews: false,
        pr_require_last_push_approval: false,
        pr_require_code_owner_review: false,
        required_linear_history,
        non_fast_forward,
        deletion,
        has_bypass_actors,
    }
}

#[test]
fn admin_enforcement_org_no_rulesets_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(false, false, false, false, false);
    let o = admin_enforcement::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.summary.to_ascii_lowercase().contains("no active"));
}

#[test]
fn admin_enforcement_org_bypass_actors_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(true, false, false, false, true);
    let o = admin_enforcement::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.summary.to_ascii_lowercase().contains("bypass"));
}

#[test]
fn admin_enforcement_org_clean_passes() {
    let mut c = base_ctx();
    c.rulesets = rulesets(true, false, false, false, false);
    assert_eq!(admin_enforcement::org_check(&c).status, Status::Pass);
}

#[test]
fn linear_history_org_required_passes() {
    let mut c = base_ctx();
    c.rulesets = rulesets(true, true, false, false, false);
    assert_eq!(linear_history::org_check(&c).status, Status::Pass);
}

#[test]
fn linear_history_org_not_required_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(true, false, false, false, false);
    assert_eq!(linear_history::org_check(&c).status, Status::Fail);
}

#[test]
fn immutable_branch_org_both_blocked_passes() {
    let mut c = base_ctx();
    c.rulesets = rulesets(true, false, true, true, false);
    assert_eq!(immutable_branch::org_check(&c).status, Status::Pass);
}

#[test]
fn immutable_branch_org_missing_one_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(true, false, true, false, false);
    let o = immutable_branch::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("deletions"))
    );
}

#[test]
fn immutable_branch_org_missing_both_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(true, false, false, false, false);
    let o = immutable_branch::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert_eq!(o.items.len(), 2);
}

#[tokio::test]
async fn org_context_fetch_aggregates_all_endpoints() {
    let client = FakeGitHubClient::new()
        .with_json(
            "/orgs/acme",
            json!({
                "two_factor_requirement_enabled": true,
                "default_repository_permission": "read",
                "plan": { "name": "team" }
            }),
        )
        .with_json(
            "/orgs/acme/settings/immutable-releases",
            json!({ "enforced_repositories": "all" }),
        )
        .with_json(
            "/orgs/acme/actions/permissions/fork-pr-contributor-approval",
            json!({ "approval_policy": "all_external_contributors" }),
        )
        .with_json(
            "/orgs/acme/actions/permissions/workflow",
            json!({ "default_workflow_permissions": "read" }),
        )
        .with_json(
            "/orgs/acme/code-security/configurations/defaults",
            json!([
                {
                    "default_for_new_repos": "all",
                    "configuration": {
                        "secret_scanning": "enabled",
                        "secret_scanning_push_protection": "enabled",
                        "dependabot_alerts": "enabled",
                        "dependabot_security_updates": "enabled",
                        "private_vulnerability_reporting": "enabled"
                    }
                }
            ]),
        )
        .with_paginated(
            "/orgs/acme/members?filter=2fa_disabled",
            vec![json!({ "login": "alice" })],
        )
        .with_paginated(
            "/orgs/acme/members?role=admin",
            vec![json!({ "login": "owner" })],
        )
        .with_paginated("/orgs/acme/outside_collaborators", vec![])
        .with_paginated("/orgs/acme/hooks", vec![])
        .with_paginated("/orgs/acme/rulesets", vec![])
        .with_paginated("/orgs/acme/repos?type=all", vec![]);

    let ctx = OrgContext::fetch(&client, "acme").await.unwrap();

    assert!(matches!(ctx.two_factor_required, TwoFactorState::Required));
    assert!(matches!(ctx.workflow_token, WorkflowTokenState::Read));
    assert!(matches!(
        ctx.secret_scanning_default,
        FeatureDefaultState::Enabled
    ));
    assert!(matches!(
        ctx.push_protection_default,
        FeatureDefaultState::Enabled
    ));
    assert!(matches!(
        ctx.dependabot_alerts_default,
        FeatureDefaultState::Enabled
    ));
    assert!(matches!(
        ctx.dependabot_security_updates_default,
        FeatureDefaultState::Enabled
    ));
    assert_eq!(ctx.members_without_2fa, vec!["alice".to_string()]);
    assert!(ctx.outside_collaborators.is_empty());
    assert_eq!(ctx.admins, vec!["owner".to_string()]);
}

#[test]
fn dependabot_security_updates_org_check_maps_default_states() {
    let mut c = ctx(TwoFactorState::Required, vec![], vec![], vec![]);

    c.dependabot_security_updates_default = FeatureDefaultState::Enabled;
    assert_eq!(
        dependabot_security_updates::org_check(&c).status,
        Status::Pass
    );

    c.dependabot_security_updates_default = FeatureDefaultState::Disabled;
    assert_eq!(
        dependabot_security_updates::org_check(&c).status,
        Status::Fail
    );

    c.dependabot_security_updates_default = FeatureDefaultState::NotSet;
    assert_eq!(
        dependabot_security_updates::org_check(&c).status,
        Status::Warn
    );
}

#[tokio::test]
async fn org_context_fetch_bails_on_forbidden_members_endpoint() {
    let client = FakeGitHubClient::new()
        .with_json(
            "/orgs/acme",
            json!({
                "two_factor_requirement_enabled": true,
                "default_repository_permission": "read",
                "plan": { "name": "team" }
            }),
        )
        .with_json(
            "/orgs/acme/settings/immutable-releases",
            json!({ "enforced_repositories": "all" }),
        )
        .with_json(
            "/orgs/acme/actions/permissions/fork-pr-contributor-approval",
            json!({ "approval_policy": "all_external_contributors" }),
        )
        .with_json(
            "/orgs/acme/actions/permissions/workflow",
            json!({ "default_workflow_permissions": "read" }),
        )
        .with_json(
            "/orgs/acme/code-security/configurations/defaults",
            json!([]),
        )
        .with_forbidden("/orgs/acme/members?filter=2fa_disabled")
        .with_paginated("/orgs/acme/members?role=admin", vec![])
        .with_paginated("/orgs/acme/outside_collaborators", vec![])
        .with_paginated("/orgs/acme/hooks", vec![])
        .with_paginated("/orgs/acme/rulesets", vec![])
        .with_paginated("/orgs/acme/repos?type=all", vec![]);

    let err = OrgContext::fetch(&client, "acme")
        .await
        .err()
        .expect("expected bail on 403");
    assert!(
        err.to_string().contains("missing permission"),
        "unexpected error: {err}"
    );
}

fn rulesets_with_pr(
    pull_request: bool,
    dismiss: bool,
    last_push: bool,
    code_owner: bool,
) -> OrgRulesets {
    OrgRulesets {
        any_active: true,
        required_signatures: false,
        pull_request,
        pr_dismiss_stale_reviews: dismiss,
        pr_require_last_push_approval: last_push,
        pr_require_code_owner_review: code_owner,
        required_linear_history: false,
        non_fast_forward: false,
        deletion: false,
        has_bypass_actors: false,
    }
}

#[test]
fn pr_reviews_org_check_no_pull_request_rule_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets_with_pr(false, true, true, true);
    let o = pr_reviews_org::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.summary.to_ascii_lowercase().contains("not required"));
}

#[test]
fn pr_reviews_org_check_lists_missing_sub_requirements() {
    let mut c = base_ctx();
    c.rulesets = rulesets_with_pr(true, false, false, false);
    let o = pr_reviews_org::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.items.iter().any(|i| {
        i.to_ascii_lowercase()
            .contains("stale reviews not dismissed")
    }));
    assert!(o.items.iter().any(|i| {
        i.to_ascii_lowercase()
            .contains("last-push approval not required")
    }));
    assert!(o.items.iter().any(|i| {
        i.to_ascii_lowercase()
            .contains("code-owner review not required")
    }));
}

#[test]
fn pr_reviews_org_check_passes_when_all_sub_flags_set() {
    let mut c = base_ctx();
    c.rulesets = rulesets_with_pr(true, true, true, true);
    let o = pr_reviews_org::org_check(&c);
    assert_eq!(o.status, Status::Pass);
}
