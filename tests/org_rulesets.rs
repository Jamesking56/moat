use moat::checks::org_context::{RulesetsState, fetch_org_rulesets};
use moat::support::github::FakeGitHubClient;
use serde_json::json;

fn summaries(ids: &[u64]) -> serde_json::Value {
    json!(
        ids.iter()
            .map(|id| json!({ "id": id, "enforcement": "active" }))
            .collect::<Vec<_>>()
    )
}

fn org_wide_conditions() -> serde_json::Value {
    json!({
        "ref_name": { "include": ["~ALL"], "exclude": [] },
        "repository_name": { "include": ["~ALL"], "exclude": [] },
    })
}

fn ruleset(rules: serde_json::Value, conditions: serde_json::Value) -> serde_json::Value {
    json!({
        "target": "branch",
        "conditions": conditions,
        "rules": rules,
        "bypass_actors": [],
    })
}

#[tokio::test]
async fn flags_all_rule_types_when_ruleset_covers_all_repos_and_default_branch() {
    let client = FakeGitHubClient::new()
        .with_paginated(
            "/orgs/acme/rulesets",
            summaries(&[1]).as_array().unwrap().clone(),
        )
        .with_json(
            "/orgs/acme/rulesets/1",
            ruleset(
                json!([
                    { "type": "required_signatures" },
                    { "type": "pull_request", "parameters": { "required_approving_review_count": 2 } },
                    { "type": "required_linear_history" },
                    { "type": "non_fast_forward" },
                    { "type": "deletion" },
                ]),
                json!({
                    "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] },
                    "repository_name": { "include": ["~ALL"], "exclude": [] },
                }),
            ),
        );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(r.any_active);
    assert!(r.required_signatures);
    assert!(r.pull_request);
    assert!(r.required_linear_history);
    assert!(r.non_fast_forward);
    assert!(r.deletion);
    assert!(!r.has_bypass_actors);
}

#[tokio::test]
async fn ignores_ruleset_when_repository_name_is_not_all() {
    let client = FakeGitHubClient::new()
        .with_paginated(
            "/orgs/acme/rulesets",
            summaries(&[1]).as_array().unwrap().clone(),
        )
        .with_json(
            "/orgs/acme/rulesets/1",
            ruleset(
                json!([{ "type": "required_signatures" }]),
                json!({
                    "ref_name": { "include": ["~ALL"], "exclude": [] },
                    "repository_name": { "include": ["legacy-*"], "exclude": [] },
                }),
            ),
        );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(!r.any_active);
    assert!(!r.required_signatures);
}

#[tokio::test]
async fn ignores_ruleset_when_ref_name_is_not_all_or_default() {
    let client = FakeGitHubClient::new()
        .with_paginated(
            "/orgs/acme/rulesets",
            summaries(&[1]).as_array().unwrap().clone(),
        )
        .with_json(
            "/orgs/acme/rulesets/1",
            ruleset(
                json!([{ "type": "required_signatures" }]),
                json!({
                    "ref_name": { "include": ["refs/heads/release/*"], "exclude": [] },
                    "repository_name": { "include": ["~ALL"], "exclude": [] },
                }),
            ),
        );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(!r.any_active);
    assert!(!r.required_signatures);
}

#[tokio::test]
async fn ignores_ruleset_when_repository_name_has_excludes() {
    let client = FakeGitHubClient::new()
        .with_paginated(
            "/orgs/acme/rulesets",
            summaries(&[1]).as_array().unwrap().clone(),
        )
        .with_json(
            "/orgs/acme/rulesets/1",
            ruleset(
                json!([{ "type": "required_signatures" }]),
                json!({
                    "ref_name": { "include": ["~ALL"], "exclude": [] },
                    "repository_name": { "include": ["~ALL"], "exclude": ["sandbox"] },
                }),
            ),
        );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(!r.any_active);
}

#[tokio::test]
async fn ignores_pull_request_rule_without_required_reviews() {
    let client = FakeGitHubClient::new()
        .with_paginated(
            "/orgs/acme/rulesets",
            summaries(&[1]).as_array().unwrap().clone(),
        )
        .with_json(
            "/orgs/acme/rulesets/1",
            ruleset(
                json!([{ "type": "pull_request", "parameters": { "required_approving_review_count": 0 } }]),
                org_wide_conditions(),
            ),
        );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(r.any_active);
    assert!(!r.pull_request);
}

#[tokio::test]
async fn ignores_pull_request_rule_when_parameters_missing() {
    let client = FakeGitHubClient::new()
        .with_paginated(
            "/orgs/acme/rulesets",
            summaries(&[1]).as_array().unwrap().clone(),
        )
        .with_json(
            "/orgs/acme/rulesets/1",
            ruleset(json!([{ "type": "pull_request" }]), org_wide_conditions()),
        );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(!r.pull_request);
}

#[tokio::test]
async fn skips_non_branch_target_rulesets() {
    let client = FakeGitHubClient::new()
        .with_paginated(
            "/orgs/acme/rulesets",
            summaries(&[1]).as_array().unwrap().clone(),
        )
        .with_json(
            "/orgs/acme/rulesets/1",
            json!({
                "target": "tag",
                "conditions": org_wide_conditions(),
                "rules": [{ "type": "required_signatures" }],
                "bypass_actors": [],
            }),
        );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(!r.any_active);
    assert!(!r.required_signatures);
}

#[tokio::test]
async fn skips_ruleset_with_repository_id_restriction() {
    let client = FakeGitHubClient::new()
        .with_paginated(
            "/orgs/acme/rulesets",
            summaries(&[1]).as_array().unwrap().clone(),
        )
        .with_json(
            "/orgs/acme/rulesets/1",
            ruleset(
                json!([{ "type": "required_signatures" }]),
                json!({
                    "ref_name": { "include": ["~ALL"], "exclude": [] },
                    "repository_name": { "include": ["~ALL"], "exclude": [] },
                    "repository_id": { "repository_ids": [42] },
                }),
            ),
        );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(!r.any_active);
}

#[tokio::test]
async fn flags_bypass_actors_only_when_they_actually_bypass() {
    let client = FakeGitHubClient::new()
        .with_paginated(
            "/orgs/acme/rulesets",
            summaries(&[1]).as_array().unwrap().clone(),
        )
        .with_json(
            "/orgs/acme/rulesets/1",
            json!({
                "target": "branch",
                "conditions": org_wide_conditions(),
                "rules": [{ "type": "required_signatures" }],
                "bypass_actors": [{ "actor_id": 1, "actor_type": "Team", "bypass_mode": "always" }],
            }),
        );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(r.has_bypass_actors);
}

#[tokio::test]
async fn ignores_inactive_rulesets() {
    let client = FakeGitHubClient::new().with_paginated(
        "/orgs/acme/rulesets",
        vec![json!({ "id": 1, "enforcement": "evaluate" })],
    );

    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert!(!r.any_active);
    assert_eq!(r.state as u8, RulesetsState::Loaded as u8);
}

#[tokio::test]
async fn forbidden_listing_yields_no_permission() {
    let client = FakeGitHubClient::new().with_forbidden("/orgs/acme/rulesets");
    let r = fetch_org_rulesets(&client, "acme").await.unwrap();
    assert_eq!(r.state as u8, RulesetsState::NoPermission as u8);
}
