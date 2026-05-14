use moat::checks::common::WebhookInfo;
use moat::checks::org_context::{
    DefaultRepoPermissionState, FeatureDefaultState, FeatureState, ForkPrContributorApprovalState,
    MemberList, OrgContext, OrgRulesets, ReleaseImmutabilityState, RulesetsState, TwoFactorState,
    WebhooksState, WorkflowTokenState,
};
use moat::checks::{
    organization_members_all_have_two_factor as members_without_2fa,
    organization_new_members_default_to_no_permissions as default_repo_permission,
    organization_requires_two_factor as two_factor_required,
    repositories_branch_protection_applies_to_admins as admin_enforcement,
    repositories_default_branch_has_linear_history as linear_history,
    repositories_default_branch_is_locked as immutable_branch,
    repositories_fork_pull_requests_require_approval as fork_pr_approval,
    repositories_private_vulnerability_reporting_is_enabled as pvr,
    repositories_pull_requests_require_reviews as pr_reviews_org,
    repositories_releases_are_immutable as releases_immutable,
    repositories_webhooks_are_secure as webhooks_secure,
};
use moat::support::github::FakeGitHubClient;
use moat::support::outcome::Status;
use serde_json::json;

fn ctx(
    tfa: TwoFactorState,
    without: MemberList,
    outside: MemberList,
    admins: MemberList,
) -> OrgContext {
    OrgContext {
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
        webhooks: WebhooksState::Ok(Vec::new()),
        private_vulnerability_reporting: FeatureState::Enabled,
        rulesets: OrgRulesets::empty(RulesetsState::Loaded),
    }
}

#[test]
fn two_factor_required_passes_when_required() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    let o = two_factor_required::org_check(&c);
    assert_eq!(o.status, Status::Pass);
    assert_eq!(o.summary, "required for every member");
}

#[test]
fn two_factor_required_fails_when_not_required() {
    let c = ctx(
        TwoFactorState::NotRequired,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    assert_eq!(two_factor_required::org_check(&c).status, Status::Fail);
}

#[test]
fn two_factor_required_skipped_when_unknown() {
    let c = ctx(
        TwoFactorState::Unknown,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    assert_eq!(two_factor_required::org_check(&c).status, Status::Skipped);
}

#[test]
fn members_without_2fa_passes_when_empty() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    assert_eq!(members_without_2fa::org_check(&c).status, Status::Pass);
}

#[test]
fn members_without_2fa_fails_with_items_when_present() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec!["alice".into(), "bob".into()]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    let o = members_without_2fa::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.summary.contains('2'));
    assert_eq!(o.items, vec!["alice", "bob"]);
}

#[test]
fn members_without_2fa_skipped_when_no_permission() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::NoPermission,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    assert_eq!(members_without_2fa::org_check(&c).status, Status::Skipped);
}

fn base_ctx() -> OrgContext {
    ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    )
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
    c.default_repository_permission = DefaultRepoPermissionState::Unknown;
    assert_eq!(
        default_repo_permission::org_check(&c).status,
        Status::Skipped
    );
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
    c.release_immutability = ReleaseImmutabilityState::Unknown;
    assert_eq!(releases_immutable::org_check(&c).status, Status::Skipped);
}

#[test]
fn fork_pr_approval_org_states() {
    let mut c = base_ctx();
    c.fork_pr_contributor_approval = ForkPrContributorApprovalState::AllExternalContributors;
    assert_eq!(fork_pr_approval::org_check(&c).status, Status::Pass);
    c.fork_pr_contributor_approval = ForkPrContributorApprovalState::FirstTimeContributors;
    assert_eq!(fork_pr_approval::org_check(&c).status, Status::Fail);
    c.fork_pr_contributor_approval = ForkPrContributorApprovalState::Unknown;
    assert_eq!(fork_pr_approval::org_check(&c).status, Status::Skipped);
}

#[test]
fn pvr_org_states() {
    let mut c = base_ctx();
    c.private_vulnerability_reporting = FeatureState::Enabled;
    assert_eq!(pvr::org_check(&c).status, Status::Pass);
    c.private_vulnerability_reporting = FeatureState::Disabled;
    assert_eq!(pvr::org_check(&c).status, Status::Fail);
    c.private_vulnerability_reporting = FeatureState::PlanGated;
    assert_eq!(pvr::org_check(&c).status, Status::Skipped);
    c.private_vulnerability_reporting = FeatureState::Unknown;
    assert_eq!(pvr::org_check(&c).status, Status::Skipped);
}

#[test]
fn webhooks_org_empty_passes() {
    let mut c = base_ctx();
    c.webhooks = WebhooksState::Ok(Vec::new());
    assert_eq!(webhooks_secure::org_check(&c).status, Status::Pass);
}

#[test]
fn webhooks_org_no_permission_skipped() {
    let mut c = base_ctx();
    c.webhooks = WebhooksState::NoPermission;
    assert_eq!(webhooks_secure::org_check(&c).status, Status::Skipped);
}

#[test]
fn webhooks_org_insecure_fails_with_findings() {
    let mut c = base_ctx();
    c.webhooks = WebhooksState::Ok(vec![
        WebhookInfo {
            url: "http://a/h".into(),
            has_secret: true,
        },
        WebhookInfo {
            url: "https://b/h".into(),
            has_secret: false,
        },
    ]);
    let o = webhooks_secure::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert_eq!(o.items.len(), 2);
}

fn rulesets(
    state: RulesetsState,
    any_active: bool,
    required_linear_history: bool,
    non_fast_forward: bool,
    deletion: bool,
    has_bypass_actors: bool,
) -> OrgRulesets {
    OrgRulesets {
        state,
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
fn admin_enforcement_org_no_permission_skipped() {
    let mut c = base_ctx();
    c.rulesets = rulesets(
        RulesetsState::NoPermission,
        false,
        false,
        false,
        false,
        false,
    );
    assert_eq!(admin_enforcement::org_check(&c).status, Status::Skipped);
}

#[test]
fn admin_enforcement_org_no_rulesets_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(RulesetsState::Loaded, false, false, false, false, false);
    let o = admin_enforcement::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.summary.contains("no active"));
}

#[test]
fn admin_enforcement_org_bypass_actors_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(RulesetsState::Loaded, true, false, false, false, true);
    let o = admin_enforcement::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.summary.contains("bypass"));
}

#[test]
fn admin_enforcement_org_clean_passes() {
    let mut c = base_ctx();
    c.rulesets = rulesets(RulesetsState::Loaded, true, false, false, false, false);
    assert_eq!(admin_enforcement::org_check(&c).status, Status::Pass);
}

#[test]
fn linear_history_org_no_permission_skipped() {
    let mut c = base_ctx();
    c.rulesets = rulesets(
        RulesetsState::NoPermission,
        false,
        false,
        false,
        false,
        false,
    );
    assert_eq!(linear_history::org_check(&c).status, Status::Skipped);
}

#[test]
fn linear_history_org_required_passes() {
    let mut c = base_ctx();
    c.rulesets = rulesets(RulesetsState::Loaded, true, true, false, false, false);
    assert_eq!(linear_history::org_check(&c).status, Status::Pass);
}

#[test]
fn linear_history_org_not_required_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(RulesetsState::Loaded, true, false, false, false, false);
    assert_eq!(linear_history::org_check(&c).status, Status::Fail);
}

#[test]
fn immutable_branch_org_no_permission_skipped() {
    let mut c = base_ctx();
    c.rulesets = rulesets(
        RulesetsState::NoPermission,
        false,
        false,
        false,
        false,
        false,
    );
    assert_eq!(immutable_branch::org_check(&c).status, Status::Skipped);
}

#[test]
fn immutable_branch_org_both_blocked_passes() {
    let mut c = base_ctx();
    c.rulesets = rulesets(RulesetsState::Loaded, true, false, true, true, false);
    assert_eq!(immutable_branch::org_check(&c).status, Status::Pass);
}

#[test]
fn immutable_branch_org_missing_one_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(RulesetsState::Loaded, true, false, true, false, false);
    let o = immutable_branch::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.items.iter().any(|i| i.contains("deletions")));
}

#[test]
fn immutable_branch_org_missing_both_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets(RulesetsState::Loaded, true, false, false, false, false);
    let o = immutable_branch::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert_eq!(o.items.len(), 2);
}

#[tokio::test]
async fn org_context_fetch_aggregates_all_endpoints() {
    let client = FakeGitHubClient::new()
        .with_json(
            "/orgs/acme",
            json!({ "two_factor_requirement_enabled": true }),
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
                        "dependabot_alerts": "enabled"
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
    match ctx.members_without_2fa {
        MemberList::Ok(v) => assert_eq!(v, vec!["alice".to_string()]),
        _ => panic!(),
    }
    match ctx.outside_collaborators {
        MemberList::Ok(v) => assert!(v.is_empty()),
        _ => panic!(),
    }
    match ctx.admins {
        MemberList::Ok(v) => assert_eq!(v, vec!["owner".to_string()]),
        _ => panic!(),
    }
}

#[tokio::test]
async fn org_context_fetch_marks_forbidden_endpoints_as_no_permission() {
    let client = FakeGitHubClient::new()
        .with_json("/orgs/acme", json!({}))
        .with_forbidden("/orgs/acme/members")
        .with_forbidden("/orgs/acme/outside_collaborators");

    let ctx = OrgContext::fetch(&client, "acme").await.unwrap();

    assert!(matches!(ctx.two_factor_required, TwoFactorState::Unknown));
    assert!(matches!(ctx.members_without_2fa, MemberList::NoPermission));
    assert!(matches!(
        ctx.outside_collaborators,
        MemberList::NoPermission
    ));
    assert!(matches!(ctx.admins, MemberList::NoPermission));
}

fn rulesets_with_pr(
    pull_request: bool,
    dismiss: bool,
    last_push: bool,
    code_owner: bool,
) -> OrgRulesets {
    OrgRulesets {
        state: RulesetsState::Loaded,
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
fn pr_reviews_org_check_no_permission_skipped() {
    let mut c = base_ctx();
    c.rulesets = OrgRulesets::empty(RulesetsState::NoPermission);
    assert_eq!(pr_reviews_org::org_check(&c).status, Status::Skipped);
}

#[test]
fn pr_reviews_org_check_no_pull_request_rule_fails() {
    let mut c = base_ctx();
    c.rulesets = rulesets_with_pr(false, true, true, true);
    let o = pr_reviews_org::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.summary.contains("not required"));
}

#[test]
fn pr_reviews_org_check_lists_missing_sub_requirements() {
    let mut c = base_ctx();
    c.rulesets = rulesets_with_pr(true, false, false, false);
    let o = pr_reviews_org::org_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.contains("stale reviews not dismissed"))
    );
    assert!(
        o.items
            .iter()
            .any(|i| i.contains("last-push approval not required"))
    );
    assert!(
        o.items
            .iter()
            .any(|i| i.contains("code-owner review not required"))
    );
}

#[test]
fn pr_reviews_org_check_passes_when_all_sub_flags_set() {
    let mut c = base_ctx();
    c.rulesets = rulesets_with_pr(true, true, true, true);
    let o = pr_reviews_org::org_check(&c);
    assert_eq!(o.status, Status::Pass);
}
