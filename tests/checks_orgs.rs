use moat::checks::orgs::context::{
    DefaultRepoPermissionState, MemberList, OrgContext, TwoFactorState,
};
use moat::checks::orgs::{admins, members_without_2fa, outside_collaborators, two_factor_required};
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
    let o = two_factor_required::check(&c);
    assert_eq!(o.status, Status::Pass);
    assert_eq!(o.summary, "required");
}

#[test]
fn two_factor_required_fails_when_not_required() {
    let c = ctx(
        TwoFactorState::NotRequired,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    assert_eq!(two_factor_required::check(&c).status, Status::Fail);
}

#[test]
fn two_factor_required_skipped_when_unknown() {
    let c = ctx(
        TwoFactorState::Unknown,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    assert_eq!(two_factor_required::check(&c).status, Status::Skipped);
}

#[test]
fn members_without_2fa_passes_when_empty() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    assert_eq!(members_without_2fa::check(&c).status, Status::Pass);
}

#[test]
fn members_without_2fa_fails_with_items_when_present() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec!["alice".into(), "bob".into()]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    let o = members_without_2fa::check(&c);
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
    assert_eq!(members_without_2fa::check(&c).status, Status::Skipped);
}

#[test]
fn outside_collaborators_warns_when_present() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec!["x".into()]),
        MemberList::Ok(vec![]),
    );
    assert_eq!(outside_collaborators::check(&c).status, Status::Warn);
}

#[test]
fn outside_collaborators_passes_when_none() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    assert_eq!(outside_collaborators::check(&c).status, Status::Pass);
}

#[test]
fn admins_fails_when_zero() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
    );
    let o = admins::check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.summary.contains("no owner"));
}

#[test]
fn admins_warns_with_count_when_present() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::Ok(vec!["a".into(), "b".into(), "c".into()]),
    );
    let o = admins::check(&c);
    assert_eq!(o.status, Status::Warn);
    assert_eq!(o.summary, "3");
}

#[test]
fn admins_skipped_when_no_permission() {
    let c = ctx(
        TwoFactorState::Required,
        MemberList::Ok(vec![]),
        MemberList::Ok(vec![]),
        MemberList::NoPermission,
    );
    assert_eq!(admins::check(&c).status, Status::Skipped);
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
