//! Machine-readable serializations of an audit run.
//!
//! `pretty` output (the styled terminal panels) lives in `runner.rs` and
//! `support::panel`; this module is the home for the `--format json` and
//! `--format markdown` emitters.

use crate::runner::CheckResult;
use crate::support::outcome::Status;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
pub struct Report {
    pub account: String,
    pub account_kind: String,
    pub summary: Summary,
    pub checks: Vec<CheckReport>,
}

#[derive(Serialize)]
pub struct Summary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub warned: usize,
    pub skipped: usize,
    pub percent_hardened: u32,
}

#[derive(Serialize)]
pub struct CheckReport {
    pub id: String,
    pub label: String,
    pub status: Status,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub how_to_fix: String,
    pub why_enable: String,
    pub affected: Vec<AffectedRepo>,
}

#[derive(Serialize)]
pub struct AffectedRepo {
    pub repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub release_branches: Vec<String>,
}

impl Report {
    pub fn from_results(account: &str, account_kind: &str, results: &[CheckResult]) -> Self {
        let total = results.len();
        let passed = results.iter().filter(|r| r.status == Status::Pass).count();
        let failed = results.iter().filter(|r| r.status == Status::Fail).count();
        let warned = results.iter().filter(|r| r.status == Status::Warn).count();
        let skipped = results
            .iter()
            .filter(|r| r.status == Status::Skipped)
            .count();
        let percent_hardened = if total == 0 {
            100
        } else {
            (((passed + skipped) * 100) / total) as u32
        };

        let checks = results
            .iter()
            .map(|r| {
                let affected = r
                    .affected_repos
                    .iter()
                    .enumerate()
                    .map(|(i, repo)| AffectedRepo {
                        repo: repo.clone(),
                        branch: r.affected_repo_branches.get(i).cloned().flatten(),
                        release_branches: r
                            .affected_repo_release_branches
                            .get(i)
                            .cloned()
                            .unwrap_or_default(),
                    })
                    .collect();
                CheckReport {
                    id: r.check.id.to_string(),
                    label: r.check.label.to_string(),
                    status: r.status,
                    summary: r.summary.clone(),
                    description: r.description.clone(),
                    how_to_fix: r.how_to_fix.to_string(),
                    why_enable: r.check.why_enable.to_string(),
                    affected,
                }
            })
            .collect();

        Self {
            account: account.to_string(),
            account_kind: account_kind.to_string(),
            summary: Summary {
                total,
                passed,
                failed,
                warned,
                skipped,
                percent_hardened,
            },
            checks,
        }
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let kind_title = match self.account_kind.as_str() {
            "organization" => "Organization",
            "user" => "User",
            "repository" => "Repository",
            other => other,
        };
        out.push_str(&format!(
            "# Security posture — {} ({})\n\n",
            self.account, kind_title
        ));

        let s = &self.summary;
        out.push_str(&format!("**{}% hardened**\n\n", s.percent_hardened));
        out.push_str(&format!(
            "- {} passed\n- {} failed\n- {} warnings\n- {} skipped\n- {} total\n\n",
            s.passed, s.failed, s.warned, s.skipped, s.total
        ));

        out.push_str("## Checks\n\n");
        out.push_str("| Status | Check | Summary |\n");
        out.push_str("| --- | --- | --- |\n");
        for c in &self.checks {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                status_label(c.status),
                md_escape(&c.label),
                md_escape(&c.summary),
            ));
        }
        out.push('\n');

        let actionable: Vec<&CheckReport> = self
            .checks
            .iter()
            .filter(|c| matches!(c.status, Status::Fail | Status::Warn))
            .collect();

        if !actionable.is_empty() {
            out.push_str("## Details\n\n");
            for c in actionable {
                out.push_str(&format!("### {} {}\n\n", status_label(c.status), c.label));
                out.push_str(&format!("**Summary:** {}\n\n", c.summary));
                if let Some(desc) = &c.description {
                    out.push_str(&format!("**Description:** {desc}\n\n"));
                }
                out.push_str(&format!("**How to fix:** {}\n\n", c.how_to_fix));
                if !c.affected.is_empty() {
                    out.push_str("**Affected:**\n\n");
                    for a in &c.affected {
                        match &a.branch {
                            Some(b) => out.push_str(&format!("- `{}` (`{}`)\n", a.repo, b)),
                            None => out.push_str(&format!("- `{}`\n", a.repo)),
                        }
                    }
                    out.push('\n');
                }
            }
        }

        out
    }

    pub fn write_json<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let s = self.to_json().map_err(io::Error::other)?;
        w.write_all(s.as_bytes())?;
        w.write_all(b"\n")
    }

    pub fn write_markdown<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(self.to_markdown().as_bytes())
    }
}

fn status_label(s: Status) -> &'static str {
    match s {
        Status::Pass => "✓ pass",
        Status::Fail => "✕ fail",
        Status::Warn => "! warn",
        Status::Skipped => "· skipped",
    }
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::CHECKS;
    use crate::runner::CheckResult;

    fn sample_results() -> Vec<CheckResult> {
        let check = &CHECKS[0];
        vec![
            CheckResult {
                check,
                status: Status::Fail,
                summary: "two repos missing config".into(),
                description: Some("note text".into()),
                how_to_fix: "",
                affected_repos: vec!["repo-a".into(), "repo-b".into()],
                affected_repo_branches: vec![Some("main".into()), None],
                affected_repo_release_branches: vec![vec![], vec!["release/1.0".into()]],
                org_default_issue: false,
                org_only_issue: false,
                private_repos_excluded_by_plan: 0,
                private_repos_in_scope: 0,
                private_repos_filtered_out: 0,
                repos_skipped_no_data: 0,
                no_data_label: None,
                skip_reason: None,
            },
            CheckResult {
                check,
                status: Status::Pass,
                summary: "all good".into(),
                description: None,
                how_to_fix: "",
                affected_repos: vec![],
                affected_repo_branches: vec![],
                affected_repo_release_branches: vec![],
                org_default_issue: false,
                org_only_issue: false,
                private_repos_excluded_by_plan: 0,
                private_repos_in_scope: 0,
                private_repos_filtered_out: 0,
                repos_skipped_no_data: 0,
                no_data_label: None,
                skip_reason: None,
            },
        ]
    }

    #[test]
    fn summary_counts_and_percentage() {
        let results = sample_results();
        let r = Report::from_results("acme", "organization", &results);
        assert_eq!(r.summary.total, 2);
        assert_eq!(r.summary.passed, 1);
        assert_eq!(r.summary.failed, 1);
        assert_eq!(r.summary.warned, 0);
        assert_eq!(r.summary.skipped, 0);
        assert_eq!(r.summary.percent_hardened, 50);
    }

    #[test]
    fn empty_results_are_fully_hardened() {
        let r = Report::from_results("acme", "user", &[]);
        assert_eq!(r.summary.total, 0);
        assert_eq!(r.summary.percent_hardened, 100);
    }

    #[test]
    fn affected_zips_parallel_vectors() {
        let r = Report::from_results("acme", "organization", &sample_results());
        let failing = &r.checks[0];
        assert_eq!(failing.affected.len(), 2);
        assert_eq!(failing.affected[0].repo, "repo-a");
        assert_eq!(failing.affected[0].branch.as_deref(), Some("main"));
        assert!(failing.affected[0].release_branches.is_empty());
        assert_eq!(failing.affected[1].repo, "repo-b");
        assert!(failing.affected[1].branch.is_none());
        assert_eq!(failing.affected[1].release_branches, vec!["release/1.0"]);
    }

    #[test]
    fn json_round_trips() {
        let r = Report::from_results("acme", "organization", &sample_results());
        let s = r.to_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["account"], "acme");
        assert_eq!(v["account_kind"], "organization");
        assert_eq!(v["summary"]["total"], 2);
        assert_eq!(v["summary"]["failed"], 1);
        assert_eq!(v["summary"]["percent_hardened"], 50);
        assert_eq!(v["checks"][0]["status"], "fail");
        assert_eq!(v["checks"][1]["status"], "pass");
        assert_eq!(v["checks"][0]["affected"][0]["repo"], "repo-a");
        assert_eq!(v["checks"][0]["affected"][0]["branch"], "main");
        assert_eq!(v["checks"][0]["description"], "note text");
        // Pass check should not serialize `description` (skip-if-none).
        assert!(v["checks"][1]["description"].is_null());
        // `org_default_issue` / `org_only_issue` are runner-internal and not exposed in JSON.
        assert!(v["checks"][0]["org_default_issue"].is_null());
        assert!(v["checks"][0]["org_only_issue"].is_null());
    }

    #[test]
    fn markdown_contains_headings_table_and_details() {
        let r = Report::from_results("acme", "organization", &sample_results());
        let md = r.to_markdown();
        assert!(md.contains("# Security posture — acme (Organization)"));
        assert!(md.contains("**50% hardened**"));
        assert!(md.contains("## Checks"));
        assert!(md.contains("| Status | Check | Summary |"));
        assert!(md.contains("## Details"));
        assert!(md.contains("**Description:** note text"));
        assert!(md.contains("**How to fix:**"));
        assert!(md.contains("`repo-a`"));
        assert!(md.contains("(`main`)"));
        // Passing checks should not appear in details section.
        let details_idx = md.find("## Details").unwrap();
        assert!(!md[details_idx..].contains("all good"));
    }

    #[test]
    fn markdown_escapes_pipes_in_summary() {
        let mut results = sample_results();
        results[0].summary = "a | b".into();
        let r = Report::from_results("acme", "organization", &results);
        let md = r.to_markdown();
        assert!(md.contains("a \\| b"));
    }

    #[test]
    fn write_json_appends_newline() {
        let r = Report::from_results("acme", "user", &[]);
        let mut buf: Vec<u8> = Vec::new();
        r.write_json(&mut buf).unwrap();
        assert!(buf.ends_with(b"\n"));
    }
}
