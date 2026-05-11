use assert_cmd::Command;
use moat::runner::{self, AccountKind};
use moat::support::github::Client;
use predicates::prelude::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn moat() -> Command {
    let mut c = Command::cargo_bin("moat").unwrap();
    c.env_remove("GH_TOKEN").env("GITHUB_TOKEN", "test-token");
    c
}

async fn stub_org(server: &MockServer, org: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/users/{org}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "Organization"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/orgs/{org}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "two_factor_requirement_enabled": true
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/orgs/{org}/members")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/orgs/{org}/outside_collaborators")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/orgs/{org}/repos")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "name": "demo",
                "archived": false,
                "fork": false,
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": { "status": "enabled" },
                    "secret_scanning_push_protection": { "status": "enabled" }
                }
            }
        ])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/{org}/demo/branches/main/protection")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "required_signatures": { "enabled": true },
            "required_pull_request_reviews": {}
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/repos/{org}/demo/actions/permissions/workflow"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "default_workflow_permissions": "read"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/{org}/demo/vulnerability-alerts")))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
}

#[tokio::test]
async fn detect_account_resolves_organization() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/acme"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "type": "Organization" })),
        )
        .mount(&server)
        .await;
    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let k = runner::detect_account(&client, "acme").await.unwrap();
    assert!(matches!(k, AccountKind::Organization));
}

#[tokio::test]
async fn detect_account_resolves_user() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/nuno"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "type": "User" })),
        )
        .mount(&server)
        .await;
    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let k = runner::detect_account(&client, "nuno").await.unwrap();
    assert!(matches!(k, AccountKind::User));
}

#[tokio::test]
async fn detect_account_404_is_friendly_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/ghost"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let e = runner::detect_account(&client, "ghost").await.unwrap_err();
    assert!(e.to_string().contains("ghost"));
}

#[tokio::test]
async fn detect_account_403_is_scope_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/secret"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    let e = runner::detect_account(&client, "secret").await.unwrap_err();
    assert!(e.to_string().contains("scope"));
}

#[tokio::test]
async fn run_org_checks_completes_against_mocked_server() {
    let server = MockServer::start().await;
    stub_org(&server, "acme").await;
    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    runner::run_org_checks(&client, "acme").await.unwrap();
}

#[tokio::test]
async fn run_repo_checks_completes_against_mocked_server() {
    let server = MockServer::start().await;
    stub_org(&server, "acme").await;
    let client = Client::with_base_url("t".into(), server.uri()).unwrap();
    runner::run_repo_checks(&client, "acme", AccountKind::Organization)
        .await
        .unwrap();
}

#[tokio::test]
async fn full_cli_audit_against_mocked_github() {
    let server = MockServer::start().await;
    stub_org(&server, "acme").await;

    moat()
        .env("MOAT_GITHUB_API_BASE", server.uri())
        .args(["audit", "acme"])
        .assert()
        .success()
        .stdout(predicate::str::contains("moat"))
        .stdout(predicate::str::contains("acme"))
        .stdout(predicate::str::contains("ORGANIZATION"))
        .stdout(predicate::str::contains("REPOSITORIES"))
        .stdout(predicate::str::contains("demo"))
        .stdout(predicate::str::contains("SUMMARY"));
}

#[tokio::test]
async fn cli_audit_only_org_skips_repos_section() {
    let server = MockServer::start().await;
    stub_org(&server, "acme").await;

    moat()
        .env("MOAT_GITHUB_API_BASE", server.uri())
        .args(["audit", "acme", "--only", "org"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ORGANIZATION"))
        .stdout(predicate::str::contains("REPOSITORIES").not());
}

#[tokio::test]
async fn cli_audit_only_repos_skips_org_section() {
    let server = MockServer::start().await;
    stub_org(&server, "acme").await;

    moat()
        .env("MOAT_GITHUB_API_BASE", server.uri())
        .args(["audit", "acme", "--only", "repos"])
        .assert()
        .success()
        .stdout(predicate::str::contains("REPOSITORIES"))
        .stdout(predicate::str::contains("ORGANIZATION").not());
}

#[tokio::test]
async fn cli_audit_user_skips_org_section_with_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/nuno"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "type": "User" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/users/nuno/repos"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    moat()
        .env("MOAT_GITHUB_API_BASE", server.uri())
        .args(["audit", "nuno"])
        .assert()
        .success()
        .stdout(predicate::str::contains("user"))
        .stdout(predicate::str::contains("skipped"));
}
