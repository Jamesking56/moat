use moat::checks::org_context::{
    DefaultRepoPermissionState, FeatureDefaultState, FeatureState, ForkPrContributorApprovalState,
    MemberList, OrgContext, OrgRulesets, ReleaseImmutabilityState, RulesetsState, TwoFactorState,
    WebhooksState, WorkflowTokenState,
};
use moat::checks::{
    organization_members_all_have_two_factor as members_without_2fa,
    organization_requires_two_factor as two_factor_required,
};
use moat::support::github::Client;
use moat::support::outcome::Status;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

#[tokio::test]
async fn org_context_fetch_aggregates_all_endpoints() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "two_factor_requirement_enabled": true
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/actions/permissions/workflow"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "default_workflow_permissions": "read"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/code-security/configurations/defaults"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "default_for_new_repos": "all",
                "configuration": {
                    "secret_scanning": "enabled",
                    "secret_scanning_push_protection": "enabled",
                    "dependabot_alerts": "enabled"
                }
            }
        ])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(query_param("filter", "2fa_disabled"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"login": "alice"}
        ])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/outside_collaborators"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(query_param("role", "admin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"login": "owner"}
        ])))
        .mount(&server)
        .await;

    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
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
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/outside_collaborators"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let ctx = OrgContext::fetch(&client, "acme").await.unwrap();

    assert!(matches!(ctx.two_factor_required, TwoFactorState::Unknown));
    assert!(matches!(ctx.members_without_2fa, MemberList::NoPermission));
    assert!(matches!(
        ctx.outside_collaborators,
        MemberList::NoPermission
    ));
    assert!(matches!(ctx.admins, MemberList::NoPermission));
}
