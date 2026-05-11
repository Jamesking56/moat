use moat::checks::repos::context::{
    BranchProtectionState, FeatureState, FeatureStatus, FilePresence, RepoContext, RepoListing,
    SecurityAndAnalysis, WebhooksState, WorkflowTokenState,
};
use moat::checks::repos::{
    branch_protection, dependabot_alerts, pr_reviews, push_protection, secret_scanning,
    signed_commits, workflow_token,
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
        require_code_owner_reviews: false,
        required_linear_history: false,
        allow_force_pushes: false,
        allow_deletions: false,
    }
}

fn ctx(branch: BranchProtectionState, token: WorkflowTokenState) -> RepoContext {
    RepoContext {
        name: "r".into(),
        archived: false,
        default_branch: Some("main".into()),
        branch_protection: branch,
        workflow_token: token,
        secret_scanning: FeatureState::Enabled,
        push_protection: FeatureState::Enabled,
        dependabot_alerts: FeatureState::Enabled,
        workflows: WorkflowsState::Loaded(Vec::new()),
        codeowners: FilePresence::Absent,
        security_md: FilePresence::Absent,
        webhooks: WebhooksState::Ok(Vec::new()),
        config: moat::config::Config::default(),
    }
}

#[test]
fn branch_protection_states() {
    assert_eq!(
        branch_protection::check(&ctx(protected(false, false), WorkflowTokenState::Read)).status,
        Status::Pass
    );
    assert_eq!(
        branch_protection::check(&ctx(
            BranchProtectionState::Unprotected,
            WorkflowTokenState::Read
        ))
        .status,
        Status::Fail
    );
    assert_eq!(
        branch_protection::check(&ctx(
            BranchProtectionState::NoDefaultBranch,
            WorkflowTokenState::Read
        ))
        .status,
        Status::Skipped
    );
    assert_eq!(
        branch_protection::check(&ctx(
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
        r.branch_protection,
        BranchProtectionState::Protected {
            signed_commits: true,
            pr_reviews: true,
            ..
        }
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
        r.branch_protection,
        BranchProtectionState::Unprotected
    ));
    assert!(matches!(r.workflow_token, WorkflowTokenState::Write));
    assert!(matches!(r.secret_scanning, FeatureState::Unknown));
    assert!(matches!(r.dependabot_alerts, FeatureState::Disabled));
}

#[tokio::test]
async fn repo_context_fetch_forks_short_circuit() {
    let server = MockServer::start().await;
    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let mut l = listing(Some("main"), None);
    l.fork = true;
    let r = RepoContext::fetch(&client, "acme", l).await.unwrap();
    assert!(matches!(
        r.branch_protection,
        BranchProtectionState::NoDefaultBranch
    ));
    assert!(matches!(r.workflow_token, WorkflowTokenState::NoPermission));
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
    assert!(matches!(
        r.branch_protection,
        BranchProtectionState::NoDefaultBranch
    ));
    assert!(matches!(r.workflow_token, WorkflowTokenState::NoPermission));
    assert!(matches!(r.dependabot_alerts, FeatureState::Unknown));
}
