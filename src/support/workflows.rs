use crate::support::github::{Fetch, GitHubClient};
use anyhow::Result;
use futures::future::try_join_all;
use serde::Deserialize;
use serde_yaml::Value;

pub enum WorkflowsState {
    Loaded(Vec<Workflow>),
    NoPermission,
}

pub struct Workflow {
    pub path: String,
    pub doc: Value,
}

#[derive(Deserialize)]
struct ContentEntry {
    name: String,
    path: String,
    #[serde(rename = "type")]
    kind: String,
}

pub async fn fetch_workflows(
    client: &impl GitHubClient,
    owner: &str,
    repo: &str,
) -> Result<WorkflowsState> {
    let listing_path = format!("/repos/{owner}/{repo}/contents/.github/workflows");
    let entries: Vec<ContentEntry> =
        match client.get_json::<Vec<ContentEntry>>(&listing_path).await? {
            Fetch::Ok(v) => v,
            Fetch::NotFound => return Ok(WorkflowsState::Loaded(Vec::new())),
            Fetch::Forbidden => return Ok(WorkflowsState::NoPermission),
        };

    let candidates: Vec<ContentEntry> = entries
        .into_iter()
        .filter(|e| {
            if e.kind != "file" {
                return false;
            }
            let lower = e.name.to_ascii_lowercase();
            lower.ends_with(".yml") || lower.ends_with(".yaml")
        })
        .collect();

    let raws = try_join_all(candidates.iter().map(|entry| {
        let raw_path = format!("/repos/{owner}/{repo}/contents/{}", entry.path);
        async move { client.get_raw(&raw_path).await }
    }))
    .await?;

    let mut out = Vec::new();
    for (entry, raw) in candidates.into_iter().zip(raws) {
        let raw = match raw {
            Fetch::Ok(s) => s,
            Fetch::NotFound | Fetch::Forbidden => continue,
        };
        let doc = match serde_yaml::from_str::<Value>(&raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push(Workflow {
            path: entry.path,
            doc,
        });
    }
    Ok(WorkflowsState::Loaded(out))
}

/// Recursively collect every `uses:` string value found in the workflow document.
pub fn collect_uses(doc: &Value) -> Vec<String> {
    let mut out = Vec::new();
    walk_uses(doc, &mut out);
    out
}

fn walk_uses(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Mapping(m) => {
            for (k, val) in m {
                if let (Value::String(ks), Value::String(vs)) = (k, val)
                    && ks == "uses"
                {
                    out.push(vs.clone());
                }
                walk_uses(val, out);
            }
        }
        Value::Sequence(s) => {
            for item in s {
                walk_uses(item, out);
            }
        }
        _ => {}
    }
}

/// True if the value at top level mentions `pull_request_target` as an `on:` trigger.
pub fn has_pull_request_target(doc: &Value) -> bool {
    let Value::Mapping(top) = doc else {
        return false;
    };
    let Some(on) = top.get(Value::String("on".into())) else {
        return false;
    };
    match on {
        Value::String(s) => s == "pull_request_target",
        Value::Sequence(seq) => seq
            .iter()
            .any(|v| matches!(v, Value::String(s) if s == "pull_request_target")),
        Value::Mapping(m) => m.contains_key(Value::String("pull_request_target".into())),
        _ => false,
    }
}

/// Returns true if any step in the workflow uses `actions/checkout` with a `ref`
/// derived from the untrusted pull-request head (e.g. `github.event.pull_request.head.*`).
pub fn has_untrusted_checkout(doc: &Value) -> bool {
    let mut found = false;
    walk_checkout(doc, &mut found);
    found
}

fn walk_checkout(v: &Value, found: &mut bool) {
    if *found {
        return;
    }
    match v {
        Value::Mapping(m) => {
            if step_is_untrusted_checkout(m) {
                *found = true;
                return;
            }
            for (_, val) in m {
                walk_checkout(val, found);
            }
        }
        Value::Sequence(s) => {
            for item in s {
                walk_checkout(item, found);
            }
        }
        _ => {}
    }
}

fn step_is_untrusted_checkout(step: &serde_yaml::Mapping) -> bool {
    if let Some(Value::String(uses)) = step.get(Value::String("uses".into())) {
        let uses_lc = uses.to_ascii_lowercase();
        let looks_like_checkout = uses_lc.contains("checkout@") || uses_lc.contains("/checkout/");
        if looks_like_checkout
            && let Some(Value::Mapping(with)) = step.get(Value::String("with".into()))
            && let Some(Value::String(r)) = with.get(Value::String("ref".into()))
            && ref_is_untrusted(r)
        {
            return true;
        }
    }
    if let Some(Value::String(run)) = step.get(Value::String("run".into())) {
        let run_lc = run.to_ascii_lowercase();
        let does_checkout = run_lc.contains("git checkout")
            || run_lc.contains("git fetch")
            || run_lc.contains("gh pr checkout");
        if does_checkout && ref_is_untrusted(run) {
            return true;
        }
    }
    false
}

fn ref_is_untrusted(s: &str) -> bool {
    let lc = s.to_ascii_lowercase();
    lc.contains("pull_request.head") || lc.contains("head_ref")
}

pub enum PermissionsBlock<'a> {
    Missing,
    WriteAll,
    Scoped(Vec<&'a str>),
    ReadAll,
    Empty,
}

pub fn top_level_permissions(doc: &Value) -> PermissionsBlock<'_> {
    let Value::Mapping(top) = doc else {
        return PermissionsBlock::Missing;
    };
    let Some(p) = top.get(Value::String("permissions".into())) else {
        return PermissionsBlock::Missing;
    };
    parse_permissions(p)
}

/// Returns each job that declares its own `permissions:` block, paired with that
/// block's classification. Used to catch job-level writes that escalate beyond
/// a restrictive top-level grant.
pub fn job_level_permissions(doc: &Value) -> Vec<(String, PermissionsBlock<'_>)> {
    let mut out = Vec::new();
    let Value::Mapping(top) = doc else {
        return out;
    };
    let Some(Value::Mapping(jobs)) = top.get(Value::String("jobs".into())) else {
        return out;
    };
    for (name, job) in jobs {
        let Value::String(job_name) = name else {
            continue;
        };
        let Value::Mapping(jm) = job else {
            continue;
        };
        let Some(p) = jm.get(Value::String("permissions".into())) else {
            continue;
        };
        out.push((job_name.clone(), parse_permissions(p)));
    }
    out
}

fn parse_permissions(p: &Value) -> PermissionsBlock<'_> {
    match p {
        Value::String(s) if s == "write-all" => PermissionsBlock::WriteAll,
        Value::String(s) if s == "read-all" => PermissionsBlock::ReadAll,
        Value::String(_) => PermissionsBlock::Empty,
        Value::Mapping(m) => {
            let mut writes = Vec::new();
            for (k, val) in m {
                if let (Value::String(ks), Value::String(vs)) = (k, val)
                    && vs == "write"
                {
                    writes.push(ks.as_str());
                }
            }
            PermissionsBlock::Scoped(writes)
        }
        _ => PermissionsBlock::Empty,
    }
}

/// A `uses:` value is "pinned" if its ref after `@` is a 40-char hex SHA.
/// Local workflow refs (starting with `./`) and docker refs (`docker://`) are exempt.
pub fn is_pinned(uses: &str) -> bool {
    if uses.starts_with("./") || uses.starts_with("docker://") {
        return true;
    }
    let Some((_, reference)) = uses.split_once('@') else {
        return false;
    };
    reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Value {
        serde_yaml::from_str(yaml).expect("valid yaml")
    }

    #[test]
    fn untrusted_checkout_classic_pull_request_head() {
        let doc = parse(
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
        );
        assert!(has_untrusted_checkout(&doc));
    }

    #[test]
    fn untrusted_checkout_head_ref_expression() {
        let doc = parse(
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n",
        );
        assert!(has_untrusted_checkout(&doc));
    }

    #[test]
    fn untrusted_checkout_case_insensitive_uses() {
        let doc = parse(
            "jobs:\n  a:\n    steps:\n      - uses: Actions/Checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n",
        );
        assert!(has_untrusted_checkout(&doc));
    }

    #[test]
    fn untrusted_checkout_third_party_action() {
        let doc = parse(
            "jobs:\n  a:\n    steps:\n      - uses: some-org/checkout/v2@v2\n        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n",
        );
        assert!(has_untrusted_checkout(&doc));
    }

    #[test]
    fn untrusted_checkout_shell_git_checkout() {
        let doc = parse(
            "jobs:\n  a:\n    steps:\n      - run: git checkout ${{ github.event.pull_request.head.sha }}\n",
        );
        assert!(has_untrusted_checkout(&doc));
    }

    #[test]
    fn untrusted_checkout_shell_git_fetch_head_ref() {
        let doc = parse(
            "jobs:\n  a:\n    steps:\n      - run: |\n          git fetch origin ${{ github.head_ref }}\n          git checkout FETCH_HEAD\n",
        );
        assert!(has_untrusted_checkout(&doc));
    }

    #[test]
    fn untrusted_checkout_gh_pr_checkout_with_head_ref() {
        let doc =
            parse("jobs:\n  a:\n    steps:\n      - run: gh pr checkout ${{ github.head_ref }}\n");
        assert!(has_untrusted_checkout(&doc));
    }

    #[test]
    fn safe_checkout_default_ref_not_flagged() {
        let doc = parse("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n");
        assert!(!has_untrusted_checkout(&doc));
    }

    #[test]
    fn safe_checkout_explicit_main_ref_not_flagged() {
        let doc = parse(
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: main\n",
        );
        assert!(!has_untrusted_checkout(&doc));
    }

    #[test]
    fn safe_checkout_base_ref_not_flagged() {
        let doc = parse(
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.base.sha }}\n",
        );
        assert!(!has_untrusted_checkout(&doc));
    }

    #[test]
    fn safe_run_step_without_checkout_not_flagged() {
        let doc = parse("jobs:\n  a:\n    steps:\n      - run: echo ${{ github.head_ref }}\n");
        assert!(!has_untrusted_checkout(&doc));
    }

    #[test]
    fn safe_unrelated_action_with_ref_param_not_flagged() {
        let doc = parse(
            "jobs:\n  a:\n    steps:\n      - uses: some-org/deploy@v1\n        with:\n          ref: ${{ github.head_ref }}\n",
        );
        assert!(!has_untrusted_checkout(&doc));
    }

    #[test]
    fn pull_request_target_string_form_detected() {
        let doc = parse("on: pull_request_target\njobs: {}\n");
        assert!(has_pull_request_target(&doc));
    }

    #[test]
    fn pull_request_target_sequence_form_detected() {
        let doc = parse("on: [push, pull_request_target]\njobs: {}\n");
        assert!(has_pull_request_target(&doc));
    }

    #[test]
    fn pull_request_target_mapping_form_detected() {
        let doc = parse("on:\n  pull_request_target:\n    types: [opened]\njobs: {}\n");
        assert!(has_pull_request_target(&doc));
    }

    #[test]
    fn pull_request_target_absent_when_only_pull_request() {
        let doc = parse("on: pull_request\njobs: {}\n");
        assert!(!has_pull_request_target(&doc));
    }
}
