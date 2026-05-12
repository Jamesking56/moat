use moat::checks::repos::context::{
    BranchProtectionState, BranchProtections, DependabotConfigState, DirectCollaboratorsState,
    FeatureState, FeatureStatus, FilePresence, RepoContext, RepoListing, SecurityAndAnalysis,
    WebhooksState, WorkflowTokenState,
};
use moat::checks::repos::{
    dependabot_alerts, direct_collaborators, pr_reviews, protected_release_branches,
    push_protection, secret_scanning, signed_commits, workflow_token,
};
use moat::support::github::Client;
use moat::support::outcome::Status;
use moat::support::workflows::WorkflowsState;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn protected(signed_commits: bool, pr_reviews: bool) -> BranchProtectionState {
    BranchProtectionState::Protected {
        signed_commits,
        pr_reviews,
        enforce_admins: false,
        required_linear_history: false,
        allow_force_pushes: false,
        allow_deletions: false,
    }
}

fn ctx(branch: BranchProtectionState, token: WorkflowTokenState) -> RepoContext {
    RepoContext {
        name: "r".into(),
        archived: false,
        private: false,
        default_branch: Some("main".into()),
        branch_protections: BranchProtections::from_single("main", branch),
        workflow_token: token,
        secret_scanning: FeatureState::Enabled,
        push_protection: FeatureState::Enabled,
        dependabot_alerts: FeatureState::Enabled,
        workflows: WorkflowsState::Loaded(Vec::new()),
        security_md: FilePresence::Absent,
        dependabot_config: DependabotConfigState::Missing,
        webhooks: WebhooksState::Ok(Vec::new()),
        direct_collaborators: DirectCollaboratorsState::Ok(Vec::new()),
        config: moat::config::Config::default(),
    }
}

#[test]
fn branch_protection_states() {
    assert_eq!(
        protected_release_branches::check(&ctx(protected(false, false), WorkflowTokenState::Read))
            .status,
        Status::Pass
    );
    assert_eq!(
        protected_release_branches::check(&ctx(
            BranchProtectionState::Unprotected,
            WorkflowTokenState::Read
        ))
        .status,
        Status::Fail
    );
    let mut no_default = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    no_default.branch_protections = BranchProtections::none();
    assert_eq!(
        protected_release_branches::check(&no_default).status,
        Status::Skipped
    );

    assert_eq!(
        protected_release_branches::check(&ctx(
            BranchProtectionState::NoPermission,
            WorkflowTokenState::Read
        ))
        .status,
        Status::Skipped
    );
}

#[test]
fn signed_commits_flag_routing() {
    let pass = ctx(protected(true, false), WorkflowTokenState::Read);
    let fail = ctx(protected(false, true), WorkflowTokenState::Read);
    assert_eq!(signed_commits::check(&pass).status, Status::Pass);
    assert_eq!(signed_commits::check(&fail).status, Status::Fail);
}

#[test]
fn pr_reviews_flag_routing() {
    let pass = ctx(protected(false, true), WorkflowTokenState::Read);
    let fail = ctx(protected(true, false), WorkflowTokenState::Read);
    assert_eq!(pr_reviews::check(&pass).status, Status::Pass);
    assert_eq!(pr_reviews::check(&fail).status, Status::Fail);
}

#[test]
fn workflow_token_states() {
    let r = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    let w = ctx(
        BranchProtectionState::Unprotected,
        WorkflowTokenState::Write,
    );
    let n = ctx(
        BranchProtectionState::Unprotected,
        WorkflowTokenState::NoPermission,
    );
    assert_eq!(workflow_token::check(&r).status, Status::Pass);
    assert_eq!(workflow_token::check(&w).status, Status::Fail);
    assert_eq!(workflow_token::check(&n).status, Status::Skipped);
}

#[test]
fn feature_state_outcomes_cover_all_variants() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);

    c.secret_scanning = FeatureState::Enabled;
    c.push_protection = FeatureState::Disabled;
    c.dependabot_alerts = FeatureState::Unknown;

    assert_eq!(secret_scanning::check(&c).status, Status::Pass);
    assert_eq!(push_protection::check(&c).status, Status::Fail);
    assert_eq!(dependabot_alerts::check(&c).status, Status::Skipped);
}

fn listing(default_branch: Option<&str>, sa: Option<SecurityAndAnalysis>) -> RepoListing {
    RepoListing {
        name: "demo".into(),
        archived: false,
        fork: false,
        private: true,
        default_branch: default_branch.map(String::from),
        security_and_analysis: sa,
    }
}

#[tokio::test]
async fn repo_context_fetch_happy_path() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/branches/main/protection"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "required_signatures": { "enabled": true },
            "required_pull_request_reviews": { "dismiss_stale_reviews": true }
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/actions/permissions/workflow"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "default_workflow_permissions": "read"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/vulnerability-alerts"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(&client, "acme", listing(Some("main"), Some(sa)))
        .await
        .unwrap();

    assert!(matches!(
        &r.branch_protections.branches[..],
        [(
            _,
            BranchProtectionState::Protected {
                signed_commits: true,
                pr_reviews: true,
                ..
            }
        )]
    ));
    assert!(matches!(r.workflow_token, WorkflowTokenState::Read));
    assert!(matches!(r.secret_scanning, FeatureState::Enabled));
    assert!(matches!(r.push_protection, FeatureState::Enabled));
    assert!(matches!(r.dependabot_alerts, FeatureState::Enabled));
}

#[tokio::test]
async fn repo_context_fetch_unprotected_when_protection_missing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/branches/main/protection"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/actions/permissions/workflow"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "default_workflow_permissions": "write"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/vulnerability-alerts"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let r = RepoContext::fetch(&client, "acme", listing(Some("main"), None))
        .await
        .unwrap();
    assert!(matches!(
        &r.branch_protections.branches[..],
        [(_, BranchProtectionState::Unprotected)]
    ));
    assert!(matches!(r.workflow_token, WorkflowTokenState::Write));
    assert!(matches!(r.secret_scanning, FeatureState::Unknown));
    assert!(matches!(r.dependabot_alerts, FeatureState::Disabled));
}

#[tokio::test]
async fn repo_context_fetch_plan_gated_private_repo_marks_scan_and_push_plan_gated() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/branches/main/protection"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_string("{\"message\":\"Upgrade to GitHub Pro or make this repository public to enable this feature.\"}"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/actions/permissions/workflow"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "default_workflow_permissions": "read"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/vulnerability-alerts"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "disabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "disabled".into(),
        }),
    };
    let r = RepoContext::fetch(&client, "acme", listing(Some("main"), Some(sa)))
        .await
        .unwrap();

    assert!(matches!(
        &r.branch_protections.branches[..],
        [(_, BranchProtectionState::PlanGated)]
    ));
    assert!(matches!(r.secret_scanning, FeatureState::PlanGated));
    assert!(matches!(r.push_protection, FeatureState::PlanGated));
    assert!(matches!(r.dependabot_alerts, FeatureState::Enabled));
}

#[tokio::test]
async fn repo_context_fetch_forks_short_circuit() {
    let server = MockServer::start().await;
    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let mut l = listing(Some("main"), None);
    l.fork = true;
    let r = RepoContext::fetch(&client, "acme", l).await.unwrap();
    assert!(r.branch_protections.is_empty());
    assert!(matches!(r.workflow_token, WorkflowTokenState::NoPermission));
}

#[test]
fn direct_collaborators_states() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);

    c.direct_collaborators = DirectCollaboratorsState::Ok(Vec::new());
    assert_eq!(direct_collaborators::check(&c).status, Status::Pass);

    c.direct_collaborators = DirectCollaboratorsState::Ok(vec!["alice".into(), "bob".into()]);
    let outcome = direct_collaborators::check(&c);
    assert_eq!(outcome.status, Status::Fail);
    assert_eq!(outcome.summary, "2");

    c.direct_collaborators = DirectCollaboratorsState::NoPermission;
    assert_eq!(direct_collaborators::check(&c).status, Status::Skipped);
}

#[tokio::test]
async fn repo_context_fetch_direct_collaborators_populated() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/collaborators"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            { "login": "alice" }
        ])))
        .mount(&server)
        .await;

    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let r = RepoContext::fetch(&client, "acme", listing(Some("main"), None))
        .await
        .unwrap();

    match r.direct_collaborators {
        DirectCollaboratorsState::Ok(v) => assert_eq!(v, vec!["alice".to_string()]),
        _ => panic!("expected Ok"),
    }
}

#[tokio::test]
async fn repo_context_fetch_direct_collaborators_public_repo_filters_read_only() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/collaborators"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            { "login": "reader", "permissions": { "pull": true } },
            { "login": "writer", "permissions": { "push": true } }
        ])))
        .mount(&server)
        .await;

    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let mut l = listing(Some("main"), None);
    l.private = false;
    let r = RepoContext::fetch(&client, "acme", l).await.unwrap();

    match r.direct_collaborators {
        DirectCollaboratorsState::Ok(v) => assert_eq!(v, vec!["writer".to_string()]),
        _ => panic!("expected Ok"),
    }
}

#[tokio::test]
async fn repo_context_fetch_direct_collaborators_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/collaborators"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let r = RepoContext::fetch(&client, "acme", listing(Some("main"), None))
        .await
        .unwrap();

    assert!(matches!(
        r.direct_collaborators,
        DirectCollaboratorsState::NoPermission
    ));
}

#[tokio::test]
async fn repo_context_fetch_no_default_branch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/actions/permissions/workflow"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/vulnerability-alerts"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let r = RepoContext::fetch(&client, "acme", listing(None, None))
        .await
        .unwrap();
    assert!(r.branch_protections.is_empty());
    assert!(matches!(r.workflow_token, WorkflowTokenState::NoPermission));
    assert!(matches!(r.dependabot_alerts, FeatureState::Unknown));
}
