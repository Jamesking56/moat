use moat::runner::{self, AccountKind};
use moat::support::github::FakeGitHubClient;
use serde_json::json;

#[tokio::test]
async fn detect_account_resolves_organization() {
    let client =
        FakeGitHubClient::new().with_json("/users/acme", json!({ "type": "Organization" }));
    let k = runner::detect_account(&client, "acme").await.unwrap();
    assert!(matches!(k, AccountKind::Organization));
}

#[tokio::test]
async fn detect_account_resolves_user() {
    let client = FakeGitHubClient::new().with_json("/users/nuno", json!({ "type": "User" }));
    let k = runner::detect_account(&client, "nuno").await.unwrap();
    assert!(matches!(k, AccountKind::User));
}

#[tokio::test]
async fn detect_account_404_is_friendly_error() {
    let client = FakeGitHubClient::new().with_not_found("/users/ghost");
    let e = runner::detect_account(&client, "ghost").await.unwrap_err();
    assert!(e.to_string().contains("ghost"));
}

#[tokio::test]
async fn detect_account_403_is_scope_error() {
    let client = FakeGitHubClient::new().with_forbidden("/users/secret");
    let e = runner::detect_account(&client, "secret").await.unwrap_err();
    assert!(e.to_string().contains("scope"));
}

fn stub_org(org: &str) -> FakeGitHubClient {
    FakeGitHubClient::new()
        .with_json(
            format!("/orgs/{org}"),
            json!({ "two_factor_requirement_enabled": true }),
        )
        .with_paginated(format!("/orgs/{org}/members?filter=2fa_disabled"), vec![])
        .with_paginated(format!("/orgs/{org}/members?role=admin"), vec![])
        .with_paginated(format!("/orgs/{org}/outside_collaborators"), vec![])
        .with_paginated(
            format!("/orgs/{org}/repos?type=all"),
            vec![json!({
                "name": "demo",
                "archived": false,
                "fork": false,
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": { "status": "enabled" },
                    "secret_scanning_push_protection": { "status": "enabled" }
                }
            })],
        )
        .with_json(
            format!("/repos/{org}/demo/branches/main/protection"),
            json!({
                "required_signatures": { "enabled": true },
                "required_pull_request_reviews": {}
            }),
        )
        .with_json(
            format!("/repos/{org}/demo/actions/permissions/workflow"),
            json!({ "default_workflow_permissions": "read" }),
        )
        .with_status(format!("/repos/{org}/demo/vulnerability-alerts"), 204)
}

#[tokio::test]
async fn run_org_checks_completes_against_fake_client() {
    let client = stub_org("acme");
    let org = runner::fetch_org_context(&client, "acme").await.unwrap();
    let repos: Vec<moat::checks::RepoContext> = Vec::new();
    let ctx = runner::CheckContext {
        org: Some(&org),
        repos: &repos,
    };
    let results = runner::run_checks(&ctx);
    runner::render_posture_panel(&results);
    runner::render_checks_panel(&results, Some(&org), 0, false);
}

#[tokio::test]
async fn run_repo_checks_completes_against_fake_client() {
    let client = stub_org("acme");
    let contexts = runner::fetch_repo_contexts(&client, "acme", AccountKind::Organization)
        .await
        .unwrap();
    let ctx = runner::CheckContext {
        org: None,
        repos: &contexts,
    };
    let results = runner::run_checks(&ctx);
    runner::render_posture_panel(&results);
    runner::render_checks_panel(&results, None, contexts.len(), false);
}

#[tokio::test]
async fn user_account_repo_checks_with_empty_listing() {
    let client = FakeGitHubClient::new()
        .with_json("/users/nuno", json!({ "type": "User" }))
        .with_paginated("/users/nuno/repos", vec![]);
    let contexts = runner::fetch_repo_contexts(&client, "nuno", AccountKind::User)
        .await
        .unwrap();
    assert!(contexts.is_empty());
}
