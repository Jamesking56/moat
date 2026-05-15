use crate::checks::org_context::{MemberList, OrgContext};
use crate::checks::repo_context::{RepoContext, RepoListing};
use crate::checks::{CHECKS, Check, Scope};
use crate::config::InvalidConfigError;
use crate::support::github::{Fetch, GitHubClient};
use crate::support::outcome::Status;
use crate::support::panel;
use anyhow::{Result, anyhow, bail};
use futures::stream::{self, StreamExt};
use owo_colors::OwoColorize;
use serde::Deserialize;

const CONCURRENCY: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccountKind {
    Organization,
    User,
}

#[derive(Deserialize)]
struct AccountType {
    #[serde(rename = "type")]
    kind: String,
}

pub fn print_repo_header(owner: &str, repo: &str) {
    let left = format!("{owner}/{repo}");
    panel::header_panel("◈", "moat", &left, "Repository");
}

pub fn print_header(account: &str, kind: AccountKind) {
    let kind_long = match kind {
        AccountKind::Organization => "Organization",
        AccountKind::User => "User",
    };
    panel::header_panel("◈", "moat", account, kind_long);
}

#[derive(Deserialize)]
struct ViewerLogin {
    login: String,
}

#[derive(Deserialize)]
struct OrgMembership {
    role: String,
    state: String,
}

fn not_admin_bail(target: &str) -> anyhow::Error {
    anyhow!(
        "You are not an admin of `{target}`. moat requires admin access to surface the data it audits — run it on an organization or repository you administer."
    )
}

/// Pre-flight: ensure the authenticated viewer can meaningfully audit `account`.
///
/// For an org, the viewer must be an active admin. For a user account, the
/// viewer must be that user. Returns the resolved account kind so callers can
/// skip a second `detect_account` round-trip.
pub async fn ensure_viewer_can_audit_account(
    client: &impl GitHubClient,
    account: &str,
) -> Result<AccountKind> {
    let kind = detect_account(client, account).await?;
    match kind {
        AccountKind::Organization => {
            let path = format!("/user/memberships/orgs/{account}");
            match client.get_json::<OrgMembership>(&path).await? {
                Fetch::Ok(m) if m.role == "admin" && m.state == "active" => {}
                _ => return Err(not_admin_bail(account)),
            }
        }
        AccountKind::User => {
            let viewer = match client.get_json::<ViewerLogin>("/user").await? {
                Fetch::Ok(v) => v,
                _ => bail!(
                    "Could not read authenticated viewer (`GET /user`) — check your token scopes"
                ),
            };
            if !viewer.login.eq_ignore_ascii_case(account) {
                return Err(not_admin_bail(account));
            }
        }
    }
    Ok(kind)
}

/// Pre-flight: ensure the viewer is an admin of the given single repo.
pub async fn ensure_viewer_can_audit_repo(
    client: &impl GitHubClient,
    owner: &str,
    repo: &str,
) -> Result<RepoListing> {
    let listing = match client
        .get_json::<RepoListing>(&format!("/repos/{owner}/{repo}"))
        .await?
    {
        Fetch::Ok(v) => v,
        Fetch::Forbidden => return Err(not_admin_bail(&format!("{owner}/{repo}"))),
        Fetch::NotFound => bail!("no repository named `{owner}/{repo}` was found"),
    };
    let is_admin = listing
        .permissions
        .as_ref()
        .map(|p| p.admin)
        .unwrap_or(false);
    if !is_admin {
        return Err(not_admin_bail(&format!("{owner}/{repo}")));
    }
    Ok(listing)
}

pub async fn detect_account(client: &impl GitHubClient, name: &str) -> Result<AccountKind> {
    match client
        .get_json::<AccountType>(&format!("/users/{name}"))
        .await?
    {
        Fetch::Ok(a) if a.kind == "Organization" => Ok(AccountKind::Organization),
        Fetch::Ok(a) if a.kind == "User" => Ok(AccountKind::User),
        Fetch::Ok(a) => bail!("unexpected account type `{}` for `{name}`", a.kind),
        Fetch::Forbidden => Err(anyhow!(
            "No access to `{name}` — check your token scopes (`read:org` for private orgs)"
        )),
        Fetch::NotFound => bail!("no GitHub account named `{name}` was found."),
    }
}

pub async fn fetch_org_context(client: &impl GitHubClient, org: &str) -> Result<OrgContext> {
    panel::progress("Fetching organization");
    OrgContext::fetch(client, org).await
}

/// How many progress ticks an org-context fetch will emit.
pub const ORG_TICKS: usize = 11;

/// How many progress ticks a per-repo scan emits (excluding the initial "scanning N" tick).
pub const REPO_TICKS: usize = 15;

pub async fn list_repos(
    client: &impl GitHubClient,
    account: &str,
    kind: AccountKind,
) -> Result<Vec<RepoListing>> {
    let listing_path = match kind {
        AccountKind::Organization => format!("/orgs/{account}/repos?type=all"),
        AccountKind::User => format!("/users/{account}/repos"),
    };

    let listings: Vec<RepoListing> = match client.get_paginated(&listing_path).await? {
        Fetch::Ok(v) => v,
        Fetch::Forbidden => {
            bail!("No permission to list repositories for `{account}` — check your token scopes")
        }
        Fetch::NotFound => Vec::new(),
    };
    Ok(listings
        .into_iter()
        .filter(|r| !r.fork && !r.archived)
        .collect())
}

pub async fn fetch_repo_contexts_from(
    client: &impl GitHubClient,
    account: &str,
    listings: Vec<RepoListing>,
) -> Result<Vec<RepoContext>> {
    fetch_contexts(client, account, listings).await
}

pub async fn fetch_repo_contexts(
    client: &impl GitHubClient,
    account: &str,
    kind: AccountKind,
) -> Result<Vec<RepoContext>> {
    let listings = list_repos(client, account, kind).await?;
    fetch_contexts(client, account, listings).await
}

pub async fn fetch_single_repo_context(
    client: &impl GitHubClient,
    owner: &str,
    listing: RepoListing,
) -> Result<Vec<RepoContext>> {
    fetch_contexts(client, owner, vec![listing]).await
}

async fn fetch_contexts(
    client: &impl GitHubClient,
    account: &str,
    listings: Vec<RepoListing>,
) -> Result<Vec<RepoContext>> {
    let total = listings.len();
    panel::progress(&format!("Scanning {total} repositories"));

    let mut stream = stream::iter(listings)
        .map(|listing| async move { RepoContext::fetch(client, account, listing).await })
        .buffer_unordered(CONCURRENCY);

    let mut contexts: Vec<RepoContext> = Vec::new();
    while let Some(r) = stream.next().await {
        match r {
            Ok(c) => contexts.push(c),
            Err(e) => {
                if e.is::<InvalidConfigError>() {
                    return Err(e);
                }
                eprintln!("  {} {e}", "!".red());
            }
        }
    }

    contexts.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(contexts)
}

pub struct CheckContext<'a> {
    pub org: Option<&'a OrgContext>,
    pub repos: &'a [RepoContext],
}

pub struct CheckResult {
    pub check: &'static Check,
    pub status: Status,
    pub summary: String,
    pub state_note: Option<String>,
    pub affected_repos: Vec<String>,
    pub affected_repo_branches: Vec<Option<String>>,
    pub affected_repo_release_branches: Vec<Vec<String>>,
    pub org_default_issue: bool,
    pub org_only_issue: bool,
}

pub fn exit_code(results: &[CheckResult]) -> i32 {
    if results.iter().any(|r| r.status == Status::Fail) {
        1
    } else {
        0
    }
}

pub fn run_checks(ctx: &CheckContext<'_>) -> Vec<CheckResult> {
    let active_total = ctx.repos.iter().filter(|c| !c.archived).count();

    CHECKS
        .iter()
        .filter(|c| scope_matches(c.scope(), ctx) && (!c.org_only || ctx.org.is_some()))
        .map(|check| evaluate(check, ctx, active_total))
        .collect()
}

fn scope_matches(scope: Scope, ctx: &CheckContext<'_>) -> bool {
    match scope {
        Scope::Org => ctx.org.is_some(),
        Scope::Repo | Scope::OrgAndRepo => true,
    }
}

fn evaluate(check: &'static Check, ctx: &CheckContext<'_>, active_total: usize) -> CheckResult {
    let org_outcome = match (check.org_eval, ctx.org) {
        (Some(f), Some(org)) => Some(f(org)),
        _ => None,
    };

    let mut affected: Vec<String> = Vec::new();
    let mut affected_branches: Vec<Option<String>> = Vec::new();
    let mut affected_release_branches: Vec<Vec<String>> = Vec::new();
    let mut repo_pass = 0usize;
    let mut repo_skipped = 0usize;
    let mut repo_warned = 0usize;
    let mut repo_applicable = 0usize;
    let mut repo_disabled = 0usize;
    let mut active_repos: Vec<&RepoContext> = Vec::new();
    if let Some(f) = check.repo_eval {
        for r in ctx.repos {
            if r.archived {
                continue;
            }
            if let Some(pred) = check.applies_to_repo
                && !pred(r)
            {
                continue;
            }
            if r.config.is_off(check.id) {
                repo_disabled += 1;
                continue;
            }
            active_repos.push(r);
            repo_applicable += 1;
            let outcome = f(r);
            match outcome.status {
                Status::Fail => {
                    affected.push(r.name.clone());
                    affected_branches.push(r.default_branch.clone());
                    let release = if check.ruleset_based {
                        r.branch_protections
                            .branches
                            .iter()
                            .map(|(name, _)| name.clone())
                            .collect()
                    } else {
                        Vec::new()
                    };
                    affected_release_branches.push(release);
                }
                Status::Pass => repo_pass += 1,
                Status::Warn => repo_warned += 1,
                Status::Skipped => repo_skipped += 1,
            }
        }
    }

    let plan_free = ctx
        .org
        .map(|o| o.plan == crate::checks::org_context::OrgPlan::Free)
        .unwrap_or(false);
    let mut org_failed = matches!(org_outcome.as_ref().map(|o| o.status), Some(Status::Fail));
    let mut org_warned = matches!(org_outcome.as_ref().map(|o| o.status), Some(Status::Warn));
    // On Free-plan orgs, suppress org-default findings for ruleset-based
    // checks only — org rulesets require Team/Enterprise to enforce, so the
    // org-level default is not actionable on Free. Non-ruleset org settings
    // (e.g. Actions workflow token defaults) remain configurable on Free and
    // must keep failing. Pure org-only checks (e.g. 2FA) have no repo_eval
    // and are never suppressed.
    let default_policy_only = check.ruleset_based
        && check.repo_eval.is_some()
        && (org_failed || org_warned)
        && affected.is_empty()
        && repo_warned == 0;
    if plan_free && default_policy_only {
        org_failed = false;
        org_warned = false;
    }
    let org_passed = matches!(org_outcome.as_ref().map(|o| o.status), Some(Status::Pass));
    let org_skipped = matches!(
        org_outcome.as_ref().map(|o| o.status),
        Some(Status::Skipped)
    );

    let any_repo_fail = !affected.is_empty();
    let any_repo_warn = repo_warned > 0;
    let any_repo_pass = repo_pass > 0;

    let repo_with_signal = repo_pass + repo_warned + affected.len();
    let all_repos_disabled =
        check.repo_eval.is_some() && repo_with_signal == 0 && repo_disabled > 0;

    let status = if any_repo_fail {
        Status::Fail
    } else if any_repo_warn {
        Status::Warn
    } else if all_repos_disabled {
        Status::Skipped
    } else if org_failed {
        Status::Fail
    } else if org_warned {
        Status::Warn
    } else if org_passed || any_repo_pass {
        Status::Pass
    } else if org_skipped || repo_skipped > 0 || repo_applicable == 0 {
        Status::Skipped
    } else {
        Status::Pass
    };

    let org_only_issue = (org_failed || org_warned) && !any_repo_fail && !any_repo_warn;

    let summary = build_summary(
        check,
        &org_outcome,
        affected.len(),
        repo_applicable,
        status,
        active_total,
        org_only_issue,
    );

    let state_note = (check.state_note)(crate::checks::StateCtx {
        org: ctx.org,
        repos: &active_repos,
    });

    CheckResult {
        check,
        status,
        summary,
        state_note,
        affected_repos: affected,
        affected_repo_branches: affected_branches,
        affected_repo_release_branches: affected_release_branches,
        org_default_issue: org_failed || org_warned,
        org_only_issue,
    }
}

fn build_summary(
    check: &Check,
    _org_outcome: &Option<crate::support::outcome::CheckOutcome>,
    failing_repos: usize,
    repo_applicable: usize,
    status: Status,
    active_total: usize,
    org_only_issue: bool,
) -> String {
    if matches!(check.scope(), Scope::Org) {
        return "org-wide".to_string();
    }
    if active_total == 0 {
        return String::new();
    }
    let noun = check.repo_noun();
    if org_only_issue && matches!(status, Status::Warn | Status::Fail) {
        return format!("{active_total}/{active_total} enabled · default policy missing");
    }
    let denom = if check.repo_eval.is_some() {
        repo_applicable
    } else {
        active_total
    };
    match status {
        Status::Fail => format!("{failing_repos}/{denom} {noun} failing"),
        Status::Pass => format!("{denom}/{denom} {noun} passing"),
        Status::Warn => format!("{denom} {noun} with warnings"),
        Status::Skipped => String::new(),
    }
}

pub fn render_posture_panel(results: &[CheckResult]) {
    let total = results.len();
    let passed = results.iter().filter(|r| r.status == Status::Pass).count();
    let failed = results.iter().filter(|r| r.status == Status::Fail).count();
    let warned = results.iter().filter(|r| r.status == Status::Warn).count();
    let skipped = results
        .iter()
        .filter(|r| r.status == Status::Skipped)
        .count();
    let pct = if total == 0 {
        100
    } else {
        ((passed + skipped) * 100) / total
    };

    panel::top_section("Security posture");
    panel::blank();

    let label = format!("{pct}% hardened");
    let line = panel::Line::new().space(3).styled(&label, panel::text_bold);
    panel::row(line);

    const BAR: usize = 60;
    let filled = (pct * BAR) / 100;
    let empty = BAR - filled;
    let bar_color: fn(&str) -> String = match pct {
        0..=33 => panel::danger,
        34..=66 => panel::warning,
        _ => panel::success,
    };
    let mut bar_line = panel::Line::new().space(3);
    let filled_str = "█".repeat(filled);
    bar_line = bar_line.styled(&filled_str, bar_color);
    let empty_str = "░".repeat(empty);
    bar_line = bar_line.styled(&empty_str, panel::border);
    panel::row(bar_line);

    panel::blank();

    let counts = panel::Line::new()
        .space(3)
        .styled("✓", panel::success_bold)
        .space(2)
        .styled(&format!("{passed} passed"), panel::text)
        .space(4)
        .styled("✕", panel::danger_bold)
        .space(2)
        .styled(&format!("{failed} critical"), panel::text)
        .space(4)
        .styled("!", panel::warning_bold)
        .space(2)
        .styled(&format!("{warned} warnings"), panel::text)
        .space(4)
        .styled("—", panel::muted)
        .space(2)
        .styled(&format!("{skipped} skipped"), panel::muted)
        .space(4)
        .styled("·", panel::muted)
        .space(2)
        .styled(&format!("{total} total"), panel::muted);
    panel::row(counts);

    panel::blank();
    panel::bottom();
    println!();
}

pub fn render_checks_panel(
    results: &[CheckResult],
    org: Option<&OrgContext>,
    account: &str,
    active_total: usize,
    verbose: bool,
) {
    if results.is_empty() {
        return;
    }

    let order = |s: Status| match s {
        Status::Pass => 0,
        Status::Skipped => 1,
        Status::Warn => 2,
        Status::Fail => 3,
    };
    let breadth = |r: &CheckResult| {
        if matches!(r.status, Status::Fail | Status::Warn) && r.summary == "org-wide" {
            usize::MAX
        } else {
            r.affected_repos.len()
        }
    };
    let mut sorted: Vec<&CheckResult> = results.iter().collect();
    sorted.sort_by_key(|r| (order(r.status), breadth(r)));

    panel::top_section("Checks");

    let inner = panel::width() - 2;
    let text_width = inner.saturating_sub(6);

    let count = sorted.len();
    for (i, r) in sorted.iter().enumerate() {
        panel::blank();

        type Renderer = fn(&str) -> String;
        let (severity, sev_render, badge_glyph, badge_render): (&str, Renderer, &str, Renderer) =
            match r.status {
                Status::Fail => ("CRITICAL", panel::danger_bold, "✕", panel::danger_bold),
                Status::Warn => ("WARNING", panel::warning_bold, "!", panel::warning_bold),
                Status::Pass => ("PASS", panel::success_bold, "✓", panel::success_bold),
                Status::Skipped => ("SKIPPED", panel::muted, "—", panel::muted),
            };
        let badge: (&str, fn(&str) -> String) = (badge_glyph, badge_render);

        let title = r.check.label.to_string();

        let head_left_visible = 2 + 1 + 2 + severity.chars().count() + 3 + title.chars().count();
        let head_right_visible = if r.summary.is_empty() {
            0
        } else {
            r.summary.chars().count() + 2
        };
        let fits = head_left_visible + 3 + head_right_visible <= inner;

        if fits && !r.summary.is_empty() {
            let avail = inner - head_left_visible - head_right_visible;
            let summary_render: fn(&str) -> String = if r.summary == "org-wide" {
                panel::muted
            } else {
                sev_render
            };
            let head = panel::Line::new()
                .space(2)
                .styled(badge.0, badge.1)
                .space(2)
                .styled(severity, sev_render)
                .space(3)
                .styled(&title, panel::text_bold)
                .space(avail)
                .styled(&r.summary, summary_render)
                .space(2);
            panel::row(head);
        } else if r.summary.is_empty() {
            let head = panel::Line::new()
                .space(2)
                .styled(badge.0, badge.1)
                .space(2)
                .styled(severity, sev_render)
                .space(3)
                .styled(&title, panel::text_bold);
            panel::row(head);
        } else {
            let head = panel::Line::new()
                .space(2)
                .styled(badge.0, badge.1)
                .space(2)
                .styled(severity, sev_render)
                .space(3)
                .styled(&title, panel::text_bold);
            panel::row(head);
            let summary_render: fn(&str) -> String = if r.summary == "org-wide" {
                panel::muted
            } else {
                sev_render
            };
            let summary_line = panel::Line::new()
                .space(5)
                .styled(&r.summary, summary_render);
            panel::row(summary_line);
        }

        panel::blank();

        if let Some(note) = &r.state_note {
            let line_text = format!("Currently: {note}.");
            for line in panel::wrap(&line_text, text_width) {
                let l = panel::Line::new().space(5).styled(&line, panel::text);
                panel::row(l);
            }
            panel::blank();
        }

        let why = if r.org_only_issue {
            "Every new repository inherits the organization's defaults; without this control set at the org level, the next repo someone creates lands unprotected and stays that way until somebody toggles it by hand.".to_string()
        } else {
            r.check.why_enable.replace("→", "›")
        };
        for line in panel::wrap(&why, text_width) {
            let l = panel::Line::new().space(5).styled(&line, panel::muted);
            panel::row(l);
        }

        panel::blank();

        if matches!(r.status, Status::Fail | Status::Warn) {
            let header = if r.org_default_issue {
                "Fix the default policy:"
            } else {
                "How to fix:"
            };
            let head = panel::Line::new().space(5).styled(header, panel::text_bold);
            panel::row(head);
            let repo = r.affected_repos.first().map(|s| s.as_str());
            let mut branches: Vec<String> = r
                .affected_repo_release_branches
                .iter()
                .flatten()
                .cloned()
                .collect();
            branches.sort();
            branches.dedup();
            let fix_text = substitute_fix_template(r.check.how_to_fix, account, repo, &branches);
            let hyperlinks = std::io::IsTerminal::is_terminal(&std::io::stdout());
            render_fix_block(&fix_text, text_width.saturating_sub(2), hyperlinks);
        }

        let is_finding = matches!(r.status, Status::Fail | Status::Warn);

        if is_finding && r.org_default_issue {
            panel::blank();
            let note = if r.org_only_issue {
                "Every existing repository has this enabled, but no security configuration is set as the default for newly created repositories — new repositories will be created without it"
            } else {
                "Org-wide default also flagged — fixing the default configuration's policy propagates to new repositories"
            };
            for line in panel::wrap(note, text_width) {
                let l = panel::Line::new().space(5).styled(&line, panel::accent);
                panel::row(l);
            }
        }

        let plan_free = org
            .map(|o| o.plan == crate::checks::org_context::OrgPlan::Free)
            .unwrap_or(false);
        let rules_link = is_finding && r.check.ruleset_based && plan_free;
        if rules_link {
            panel::blank();
            let note = "Organization rulesets require GitHub Team or Enterprise to enforce — on the Free plan, the rules above are saved but not applied. Either upgrade the organization, or apply equivalent rules per-repo.";
            for line in panel::wrap(note, text_width) {
                let l = panel::Line::new().space(5).styled(&line, panel::warning);
                panel::row(l);
            }
        }

        if is_finding && r.check.ruleset_based {
            panel::blank();
            let note = "Strict enforcement can create friction — for example, a solo maintainer can be blocked from merging their own changes. If that's your situation, configure this ruleset's Bypass list to choose which roles, teams, GitHub Apps, or users may bypass it, rather than weakening the rule for everyone.";
            for line in panel::wrap(note, text_width) {
                let l = panel::Line::new().space(5).styled(&line, panel::warning);
                panel::row(l);
            }
        }

        if let Some(o) = org {
            match r.check.id {
                "repositories_have_no_direct_collaborators" => {
                    render_member_block(
                        "Outside collaborators",
                        &o.outside_collaborators,
                        text_width,
                        verbose,
                    );
                }
                "repositories_branch_protection_applies_to_admins" => {
                    render_member_block("Bypass list", &o.admins, text_width, verbose);
                }
                _ => {}
            }
        }

        if is_finding && !r.affected_repos.is_empty() {
            panel::blank();
            let total = r.affected_repos.len();
            let lbl = format!("Affected repositories ({total})");
            let l = panel::Line::new().space(5).styled(&lbl, panel::accent_bold);
            panel::row(l);

            let hyperlinks = std::io::IsTerminal::is_terminal(&std::io::stdout());
            let path = if rules_link {
                Some("/settings/rules")
            } else {
                r.check.repo_link_path
            };

            let max_rows = 4usize;
            let show = if verbose || total <= max_rows {
                total
            } else {
                max_rows
            };
            for (idx, name) in r.affected_repos[..show].iter().enumerate() {
                let branch = r
                    .affected_repo_branches
                    .get(idx)
                    .and_then(|b| b.as_deref())
                    .unwrap_or("HEAD");
                let suffix = path
                    .map(|p| p.replace("{branch}", branch))
                    .unwrap_or_default();
                let url = format!("https://github.com/{account}/{name}{suffix}");
                let styled = panel::text(&url);
                let cell = if hyperlinks {
                    format!("\x1b]8;;{url}\x1b\\{styled}\x1b]8;;\x1b\\")
                } else {
                    styled
                };
                let line = panel::Line::new().space(7).raw(&url, &cell);
                panel::row(line);
            }
            if show < total {
                let more = format!("+{} more · --verbose to list", total - show);
                let line = panel::Line::new().space(7).styled(&more, panel::muted);
                panel::row(line);
            }
        }

        panel::blank();
        if i + 1 < count {
            panel::divider();
        }
    }

    panel::bottom();
    println!();

    let _ = active_total;
}

fn render_member_block(title: &str, list: &MemberList, text_width: usize, verbose: bool) {
    panel::blank();
    match list {
        MemberList::NoPermission => {
            let lbl = format!("{title} (requires org admin token)");
            let l = panel::Line::new().space(5).styled(&lbl, panel::muted);
            panel::row(l);
        }
        MemberList::Ok(v) if v.is_empty() => {
            let lbl = format!("{title} (0)");
            let l = panel::Line::new().space(5).styled(&lbl, panel::accent_bold);
            panel::row(l);
            let none = panel::Line::new().space(7).styled("None", panel::muted);
            panel::row(none);
        }
        MemberList::Ok(v) => {
            let lbl = format!("{title} ({})", v.len());
            let l = panel::Line::new().space(5).styled(&lbl, panel::accent_bold);
            panel::row(l);
            let preview: Vec<&str> = v.iter().map(String::as_str).collect();
            let rendered = if verbose || preview.len() <= 6 {
                preview.join("  ")
            } else {
                format!(
                    "{}  +{} more · --verbose to list",
                    preview[..5].join("  "),
                    preview.len() - 5
                )
            };
            for line in panel::wrap(&rendered, text_width.saturating_sub(2)) {
                let l = panel::Line::new().space(7).styled(&line, panel::text);
                panel::row(l);
            }
        }
    }
}

fn substitute_fix_template(
    template: &str,
    account: &str,
    repo: Option<&str>,
    branches: &[String],
) -> String {
    let with_org = template.replace("{org}", account);
    let with_repo = match repo {
        Some(r) => with_org.replace("{repo}", r),
        None => with_org,
    };
    let branches_text = if branches.is_empty() {
        "Default + release branches".to_string()
    } else {
        branches.join(", ")
    };
    with_repo.replace("{branches}", &branches_text)
}

#[derive(Debug)]
enum Atom<'a> {
    Plain(&'a str),
    Url(&'a str),
    Underline(&'a str),
}

fn parse_fix_atoms(s: &str) -> Vec<Atom<'_>> {
    let mut atoms = Vec::new();
    let mut rest = s;
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        if let Some(after) = rest.strip_prefix("__")
            && let Some(end) = after.find("__")
        {
            atoms.push(Atom::Underline(&after[..end]));
            rest = &after[end + 2..];
            continue;
        }
        if rest.starts_with("https://") || rest.starts_with("http://") {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            atoms.push(Atom::Url(&rest[..end]));
            rest = &rest[end..];
            continue;
        }
        let mut end = rest.len();
        for (i, _) in rest.char_indices() {
            if i == 0 {
                continue;
            }
            let cur = &rest[i..];
            if cur.starts_with(|c: char| c.is_whitespace())
                || cur.starts_with("__")
                || cur.starts_with("http://")
                || cur.starts_with("https://")
            {
                end = i;
                break;
            }
        }
        atoms.push(Atom::Plain(&rest[..end]));
        rest = &rest[end..];
    }
    atoms
}

fn atom_visible<'a>(a: &'a Atom<'a>) -> &'a str {
    match a {
        Atom::Plain(s) | Atom::Url(s) | Atom::Underline(s) => s,
    }
}

fn render_atom(a: &Atom<'_>, hyperlinks: bool) -> String {
    match a {
        Atom::Plain(s) => panel::info(s),
        Atom::Url(u) => {
            let styled = panel::info_underline(u);
            if hyperlinks {
                format!("\x1b]8;;{u}\x1b\\{styled}\x1b]8;;\x1b\\")
            } else {
                styled
            }
        }
        Atom::Underline(s) => panel::info_underline(s),
    }
}

fn render_fix_block(text: &str, width: usize, hyperlinks: bool) {
    for (i, segment) in split_fences(text).into_iter().enumerate() {
        match segment {
            FixSegment::Prose(s) => render_fix_prose(s, width, hyperlinks),
            FixSegment::Code(lines) => {
                if i > 0 {
                    panel::blank();
                }
                for line in lines {
                    let l = panel::Line::new().styled(line, panel::muted);
                    panel::raw_line(l);
                }
                panel::blank();
            }
        }
    }
}

enum FixSegment<'a> {
    Prose(&'a str),
    Code(Vec<&'a str>),
}

fn split_fences(text: &str) -> Vec<FixSegment<'_>> {
    let mut out: Vec<FixSegment<'_>> = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("```") {
        let prose = &rest[..open];
        if !prose.trim().is_empty() {
            out.push(FixSegment::Prose(prose));
        }
        let after_open = &rest[open + 3..];
        let body_start = after_open.find('\n').map(|n| n + 1).unwrap_or(0);
        let body = &after_open[body_start..];
        if let Some(close) = body.find("```") {
            let code = &body[..close];
            let lines: Vec<&str> = code.trim_end_matches('\n').split('\n').collect();
            out.push(FixSegment::Code(lines));
            rest = &body[close + 3..];
        } else {
            out.push(FixSegment::Prose(rest));
            return out;
        }
    }
    if !rest.trim().is_empty() {
        out.push(FixSegment::Prose(rest));
    }
    out
}

fn render_fix_prose(text: &str, width: usize, hyperlinks: bool) {
    let atoms = parse_fix_atoms(text);
    let mut line_atoms: Vec<&Atom<'_>> = Vec::new();
    let mut line_w = 0usize;

    let flush = |line_atoms: &[&Atom<'_>]| {
        if line_atoms.is_empty() {
            return;
        }
        let mut line = panel::Line::new().space(7);
        for (i, a) in line_atoms.iter().enumerate() {
            if i > 0 {
                line = line.space(1);
            }
            line = line.raw(atom_visible(a), &render_atom(a, hyperlinks));
        }
        panel::row(line);
    };

    for a in &atoms {
        let w = atom_visible(a).chars().count();
        let sep = if line_atoms.is_empty() { 0 } else { 1 };
        if line_w + sep + w > width && !line_atoms.is_empty() {
            flush(&line_atoms);
            line_atoms.clear();
            line_atoms.push(a);
            line_w = w;
        } else {
            line_atoms.push(a);
            line_w += sep + w;
        }
    }
    flush(&line_atoms);
}
