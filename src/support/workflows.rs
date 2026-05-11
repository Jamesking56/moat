use crate::support::github::{Client, Fetch};
use anyhow::Result;
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

pub async fn fetch_workflows(client: &Client, owner: &str, repo: &str) -> Result<WorkflowsState> {
    let listing_path = format!("/repos/{owner}/{repo}/contents/.github/workflows");
    let entries: Vec<ContentEntry> =
        match client.get_json::<Vec<ContentEntry>>(&listing_path).await? {
            Fetch::Ok(v) => v,
            Fetch::NotFound => return Ok(WorkflowsState::Loaded(Vec::new())),
            Fetch::Forbidden => return Ok(WorkflowsState::NoPermission),
        };

    let mut out = Vec::new();
    for entry in entries {
        if entry.kind != "file" {
            continue;
        }
        let lower = entry.name.to_ascii_lowercase();
        if !(lower.ends_with(".yml") || lower.ends_with(".yaml")) {
            continue;
        }
        let raw_path = format!("/repos/{owner}/{repo}/contents/{}", entry.path);
        let raw = match client.get_raw(&raw_path).await? {
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
            let is_checkout = m
                .get(Value::String("uses".into()))
                .and_then(Value::as_str)
                .map(|s| s.starts_with("actions/checkout@"))
                .unwrap_or(false);
            if is_checkout
                && let Some(Value::Mapping(with)) = m.get(Value::String("with".into()))
                && let Some(Value::String(r)) = with.get(Value::String("ref".into()))
                && r.contains("pull_request.head")
            {
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
