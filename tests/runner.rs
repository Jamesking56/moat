use moat::checks::CHECKS;
use moat::runner::{self, AccountKind, CheckResult};
use moat::support::github::FakeGitHubClient;
use moat::support::outcome::Status;
use serde_json::json;

fn result_with(status: Status) -> CheckResult {
    CheckResult {
        check: &CHECKS[0],
        status,
        summary: String::new(),
        state_note: None,
        affected_repos: Vec::new(),
        org_default_issue: false,
        org_only_issue: false,
    }
}

#[test]
fn exit_code_is_zero_when_no_failures() {
    let results = vec![
        result_with(Status::Pass),
        result_with(Status::Warn),
        result_with(Status::Skipped),
    ];
    assert_eq!(runner::exit_code(&results), 0);
}

#[test]
fn exit_code_is_one_when_any_check_fails() {
    let results = vec![result_with(Status::Pass), result_with(Status::Fail)];
    assert_eq!(runner::exit_code(&results), 1);
}

#[test]
fn exit_code_is_zero_for_empty_results() {
    assert_eq!(runner::exit_code(&[]), 0);
}

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
async fn invalid_moat_toml_aborts_the_run() {
    let client = stub_org("acme").with_raw(
        "/repos/acme/demo/contents/moat.toml",
        "[checks]\nnot_a_real_check = \"off\"\n",
    );
    let err = match runner::fetch_repo_contexts(&client, "acme", AccountKind::Organization).await {
        Ok(_) => panic!("expected fetch_repo_contexts to fail on invalid moat.toml"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("invalid moat.toml"), "got: {msg}");
    assert!(msg.contains("acme/demo"), "got: {msg}");
    assert!(msg.contains("unknown check"), "got: {msg}");
}

#[tokio::test]
async fn missing_moat_toml_continues_with_defaults() {
    // stub_org does not stub the moat.toml endpoint, so get_raw returns NotFound
    // and the run should proceed normally.
    let client = stub_org("acme");
    let contexts = runner::fetch_repo_contexts(&client, "acme", AccountKind::Organization)
        .await
        .unwrap();
    assert_eq!(contexts.len(), 1);
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
