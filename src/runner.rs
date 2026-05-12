use crate::checks::orgs::{
    OrgContext, context::MemberList, default_repo_permission,
    dependabot_alerts as org_dependabot_alerts, fork_pr_contributor_approval, members_without_2fa,
    push_protection as org_push_protection, release_immutability,
    secret_scanning as org_secret_scanning, two_factor_required,
    workflow_token as org_workflow_token,
};
use crate::checks::repos::{
    RepoContext, admin_enforcement, context::RepoListing, dependabot_alerts, dependabot_config,
    direct_collaborators, immutable_branch, linear_history, pinned_actions, pr_reviews,
    protected_release_branches, pull_request_target, push_protection, secret_scanning, security_md,
    signed_commits, webhooks, workflow_permissions, workflow_token,
};
use crate::support::github::{Client, Fetch};
use crate::support::outcome::{CheckOutcome, Status};
use crate::support::panel;
use anyhow::{Result, anyhow, bail};
use futures::stream::{self, StreamExt};
use owo_colors::OwoColorize;
use serde::Deserialize;

const CONCURRENCY: usize = 12;

type RepoCheck = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    fn(&RepoContext) -> CheckOutcome,
);

type OrgCheck = (
    &'static str,
    &'static str,
    &'static str,
    CheckOutcome,
);

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
    panel::header_panel("◈", "moat", &left, "repository");
}

pub fn print_header(account: &str, kind: AccountKind) {
    let kind_long = match kind {
        AccountKind::Organization => "organization",
        AccountKind::User => "user",
    };
    panel::header_panel("◈", "moat", account, kind_long);
}

pub async fn detect_account(client: &Client, name: &str) -> Result<AccountKind> {
    match client
        .get_json::<AccountType>(&format!("/users/{name}"))
        .await?
    {
        Fetch::Ok(a) if a.kind == "Organization" => Ok(AccountKind::Organization),
        Fetch::Ok(a) if a.kind == "User" => Ok(AccountKind::User),
        Fetch::Ok(a) => bail!("unexpected account type `{}` for `{name}`", a.kind),
        Fetch::Forbidden => Err(anyhow!(
            "no access to `{name}` — check your token scopes (`read:org` for private orgs)"
        )),
        Fetch::NotFound => bail!("no GitHub account named `{name}` was found."),
    }
}

pub async fn fetch_org_context(client: &Client, org: &str) -> Result<OrgContext> {
    panel::progress("fetching organization");
    OrgContext::fetch(client, org).await
}

pub type Suppressions = std::collections::HashMap<&'static str, std::collections::HashSet<String>>;

pub fn render_org_checks(
    ctx: &OrgContext,
    repo_contexts: Option<&[RepoContext]>,
    _verbose: bool,
) -> (Suppressions, Vec<Finding>) {
    panel::finish_progress("organization");
    let mut results: [OrgCheck; 9] = [
        (
            two_factor_required::NAME,
            two_factor_required::HOW_TO_FIX,
            two_factor_required::WHY_ENABLE,
            two_factor_required::check(ctx),
        ),
        (
            members_without_2fa::NAME,
            members_without_2fa::HOW_TO_FIX,
            members_without_2fa::WHY_ENABLE,
            members_without_2fa::check(ctx),
        ),
        (
            default_repo_permission::NAME,
            default_repo_permission::HOW_TO_FIX,
            default_repo_permission::WHY_ENABLE,
            default_repo_permission::check(ctx),
        ),
        (
            release_immutability::NAME,
            release_immutability::HOW_TO_FIX,
            release_immutability::WHY_ENABLE,
            release_immutability::check(ctx),
        ),
        (
            fork_pr_contributor_approval::NAME,
            fork_pr_contributor_approval::HOW_TO_FIX,
            fork_pr_contributor_approval::WHY_ENABLE,
            fork_pr_contributor_approval::check(ctx),
        ),
        (
            org_workflow_token::NAME,
            org_workflow_token::HOW_TO_FIX,
            org_workflow_token::WHY_ENABLE,
            org_workflow_token::check(ctx),
        ),
        (
            org_secret_scanning::NAME,
            org_secret_scanning::HOW_TO_FIX,
            org_secret_scanning::WHY_ENABLE,
            org_secret_scanning::check(ctx),
        ),
        (
            org_push_protection::NAME,
            org_push_protection::HOW_TO_FIX,
            org_push_protection::WHY_ENABLE,
            org_push_protection::check(ctx),
        ),
        (
            org_dependabot_alerts::NAME,
            org_dependabot_alerts::HOW_TO_FIX,
            org_dependabot_alerts::WHY_ENABLE,
            org_dependabot_alerts::check(ctx),
        ),
    ];

    let (affected_by_check, suppressions): (
        std::collections::HashMap<&'static str, Vec<String>>,
        Suppressions,
    ) = repo_contexts
        .map(|repos| decorate_cascades(&mut results, repos))
        .unwrap_or_default();

    render_posture_panel(&results);

    let active_total = repo_contexts
        .map(|c| c.iter().filter(|r| !r.archived).count())
        .unwrap_or(0);
    let org_findings = build_org_findings(&results, &affected_by_check, active_total);

    (suppressions, org_findings)
}

fn build_org_findings(
    results: &[OrgCheck],
    affected_by_check: &std::collections::HashMap<&'static str, Vec<String>>,
    active_total: usize,
) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for (name, how_to_fix, why_enable, outcome) in results {
        let severity = match outcome.status {
            Status::Fail => Status::Fail,
            Status::Warn => Status::Warn,
            _ => continue,
        };
        let base = name.to_uppercase_first();
        let title = if outcome.summary.is_empty() {
            base
        } else {
            format!("{base} {}", outcome.summary)
        };
        let affected_count = affected_by_check
            .get(name)
            .map(|v| v.len())
            .unwrap_or(active_total);
        out.push(Finding {
            title,
            how_to_fix,
            why_enable,
            severity,
            affected_count,
            affected_list: None,
        });
    }
    out
}

pub fn render_org_inventory(
    ctx: &OrgContext,
    repo_contexts: Option<&[RepoContext]>,
    verbose: bool,
) {
    render_inventory_panel(ctx, repo_contexts, verbose);
}

fn render_posture_panel(results: &[OrgCheck]) {
    let total = results.len();
    let passed = results.iter().filter(|(_, _, _, o)| o.status == Status::Pass).count();
    let failed = results.iter().filter(|(_, _, _, o)| o.status == Status::Fail).count();
    let warned = results.iter().filter(|(_, _, _, o)| o.status == Status::Warn).count();
    let skipped = results.iter().filter(|(_, _, _, o)| o.status == Status::Skipped).count();
    let applicable = total.saturating_sub(skipped);
    let pct = if applicable == 0 { 100 } else { (passed * 100) / applicable };

    panel::top_section("ORGANIZATION · Security posture");
    panel::blank();

    let label = format!("{pct}% hardened");
    let line = panel::Line::new().space(3).styled(&label, panel::text_bold);
    panel::row(line);

    const BAR: usize = 60;
    let filled = (pct * BAR) / 100;
    let empty = BAR - filled;
    let bar_color: fn(&str) -> String = if failed > 0 {
        panel::danger
    } else if warned > 0 {
        panel::warning
    } else {
        panel::success
    };
    let fill_str = "█".repeat(filled);
    let empty_str = "░".repeat(empty);
    let bar_line = panel::Line::new()
        .space(3)
        .styled(&fill_str, bar_color)
        .styled(&empty_str, panel::border);
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
        .styled(&format!("{warned} warning"), panel::text)
        .space(4)
        .styled("·", panel::muted)
        .space(2)
        .styled(&format!("{total} checked"), panel::muted);
    panel::row(counts);

    panel::blank();
    panel::bottom();
    println!();
}


pub struct Finding {
    title: String,
    how_to_fix: &'static str,
    why_enable: &'static str,
    severity: Status,
    affected_count: usize,
    affected_list: Option<Vec<String>>,
}

pub fn render_findings_panel(findings: &[Finding], total_active: usize, verbose: bool) {
    if findings.is_empty() {
        return;
    }

    panel::top_section("Findings");

    let inner = panel::width() - 2;
    let text_width = inner.saturating_sub(6);

    for (i, finding) in findings.iter().enumerate() {
        panel::blank();

        let (severity, sev_render): (&str, fn(&str) -> String) = match finding.severity {
            Status::Fail => ("CRITICAL", panel::danger_bold),
            _ => ("WARNING", panel::warning_bold),
        };
        let badge: (&str, fn(&str) -> String) = match finding.severity {
            Status::Fail => ("✕", panel::danger_bold),
            _ => ("!", panel::warning_bold),
        };

        let summary = if total_active > 0 {
            format!("{}/{} repos", finding.affected_count, total_active)
        } else {
            String::new()
        };

        let head_left_visible =
            2 + 1 + 2 + severity.chars().count() + 3 + finding.title.chars().count();
        let head_right_visible = if summary.is_empty() {
            0
        } else {
            summary.chars().count() + 2
        };
        let fits = head_left_visible + 3 + head_right_visible <= inner;

        if fits && !summary.is_empty() {
            let avail = inner - head_left_visible - head_right_visible;
            let head = panel::Line::new()
                .space(2)
                .styled(badge.0, badge.1)
                .space(2)
                .styled(severity, sev_render)
                .space(3)
                .styled(&finding.title, panel::text_bold)
                .space(avail)
                .styled(&summary, sev_render)
                .space(2);
            panel::row(head);
        } else if summary.is_empty() {
            let head = panel::Line::new()
                .space(2)
                .styled(badge.0, badge.1)
                .space(2)
                .styled(severity, sev_render)
                .space(3)
                .styled(&finding.title, panel::text_bold);
            panel::row(head);
        } else {
            let head = panel::Line::new()
                .space(2)
                .styled(badge.0, badge.1)
                .space(2)
                .styled(severity, sev_render)
                .space(3)
                .styled(&finding.title, panel::text_bold);
            panel::row(head);
            let summary_line = panel::Line::new().space(5).styled(&summary, sev_render);
            panel::row(summary_line);
        }

        panel::blank();

        let why = finding.why_enable.replace("→", "›");
        for line in panel::wrap(&why, text_width) {
            let l = panel::Line::new().space(5).styled(&line, panel::muted);
            panel::row(l);
        }

        panel::blank();

        let path = finding.how_to_fix.replace("→", "›");
        for line in panel::wrap(&path, text_width) {
            let l = panel::Line::new().space(5).styled(&line, panel::info);
            panel::row(l);
        }

        if let Some(affected) = &finding.affected_list
            && !affected.is_empty()
        {
            panel::blank();
            let lbl = format!("Affected repositories ({})", affected.len());
            let l = panel::Line::new().space(5).styled(&lbl, panel::accent_bold);
            panel::row(l);

            let preview: Vec<&str> = affected.iter().map(String::as_str).collect();
            let rendered = if verbose || preview.len() <= 6 {
                preview.join("  ")
            } else {
                format!("{}  +{} more", preview[..5].join("  "), preview.len() - 5)
            };
            for line in panel::wrap(&rendered, text_width) {
                let l = panel::Line::new().space(5).styled(&line, panel::text);
                panel::row(l);
            }
        }

        panel::blank();
        if i + 1 < findings.len() {
            panel::divider();
        }
    }

    panel::bottom();
    println!();
}

fn render_inventory_panel(
    ctx: &OrgContext,
    repo_contexts: Option<&[RepoContext]>,
    verbose: bool,
) {
    let inventory: &[(&str, &MemberList)] = &[
        ("outside collaborators", &ctx.outside_collaborators),
        ("org admins", &ctx.admins),
    ];

    panel::top_section("Inventory");
    panel::blank();
    let mut label_width = inventory.iter().map(|(n, _)| n.chars().count()).max().unwrap_or(0);
    if repo_contexts.is_some() {
        label_width = label_width.max("repositories".chars().count());
    }

    if let Some(repos) = repo_contexts {
        let total = repos.len();
        let active = repos.iter().filter(|c| !c.archived).count();
        let pad = label_width.saturating_sub("repositories".chars().count());
        let summary = format!("{total} total · {active} active");
        let l = panel::Line::new()
            .space(3)
            .styled("repositories", panel::text_bold)
            .space(pad + 2)
            .styled(&summary, panel::accent_bold);
        panel::row(l);
    }

    for (name, list) in inventory {
        let pad = label_width.saturating_sub(name.chars().count());
        let (summary, summary_color, items): (String, fn(&str) -> String, &[String]) = match list {
            MemberList::NoPermission => {
                ("(requires org admin token)".to_string(), panel::muted, &[])
            }
            MemberList::Ok(v) if v.is_empty() => ("none".to_string(), panel::muted, &[]),
            MemberList::Ok(v) => (v.len().to_string(), panel::accent_bold, v.as_slice()),
        };
        let l = panel::Line::new()
            .space(3)
            .styled(name, panel::text_bold)
            .space(pad + 2)
            .styled(&summary, summary_color);
        panel::row(l);
        render_inventory_items(items, verbose);
    }

    panel::blank();
    panel::bottom();
    println!();
}

fn render_inventory_items(items: &[String], verbose: bool) {
    if items.is_empty() {
        return;
    }
    const PREVIEW: usize = 5;
    let text_width = panel::width() - 2 - 7;
    let shown: Vec<&str> = items
        .iter()
        .take(if verbose { items.len() } else { PREVIEW })
        .map(String::as_str)
        .collect();
    let rest = items.len().saturating_sub(shown.len());
    let joined = if rest > 0 {
        format!("{}  +{} more", shown.join("  "), rest)
    } else {
        shown.join("  ")
    };
    for line in panel::wrap(&joined, text_width) {
        let l = panel::Line::new().space(7).styled(&line, panel::muted);
        panel::row(l);
    }
}

trait UpperFirst {
    fn to_uppercase_first(&self) -> String;
}
impl UpperFirst for &str {
    fn to_uppercase_first(&self) -> String {
        let mut chars = self.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }
}

fn decorate_cascades(
    results: &mut [OrgCheck; 9],
    repos: &[RepoContext],
) -> (
    std::collections::HashMap<&'static str, Vec<String>>,
    Suppressions,
) {
    type AffectedFn = fn(&RepoContext) -> Option<String>;
    fn fails(run: fn(&RepoContext) -> CheckOutcome, c: &RepoContext) -> Option<String> {
        (run(c).status == Status::Fail).then(|| c.name.clone())
    }
    fn dep(c: &RepoContext) -> Option<String> {
        fails(dependabot_alerts::check, c)
    }
    fn scan(c: &RepoContext) -> Option<String> {
        fails(secret_scanning::check, c)
    }
    fn push(c: &RepoContext) -> Option<String> {
        fails(push_protection::check, c)
    }
    fn token(c: &RepoContext) -> Option<String> {
        fails(workflow_token::check, c)
    }
    fn immutable(c: &RepoContext) -> Option<String> {
        if immutable_branch::check(c).status != Status::Fail {
            return None;
        }
        let branches: Vec<&str> = c
            .branch_protections
            .branches
            .iter()
            .filter(|(_, state)| immutable_branch_fails(state))
            .map(|(name, _)| name.as_str())
            .collect();
        Some(if branches.is_empty() {
            c.name.clone()
        } else {
            format!("{} ({})", c.name, branches.join(", "))
        })
    }

    let pairs: &[(&'static str, &'static str, AffectedFn)] = &[
        (org_dependabot_alerts::NAME, "dependabot_alerts", dep),
        (org_secret_scanning::NAME, "secret_scanning", scan),
        (org_push_protection::NAME, "push_protection", push),
        (org_workflow_token::NAME, "workflow_token", token),
        (release_immutability::NAME, "immutable_branch", immutable),
    ];

    let mut affected_by_check = std::collections::HashMap::new();
    let mut suppressions: Suppressions = std::collections::HashMap::new();
    for (org_name, repo_id, affected_fn) in pairs {
        let Some((_, _, _, outcome)) = results.iter_mut().find(|(n, _, _, _)| n == org_name) else {
            continue;
        };
        if outcome.status != Status::Fail {
            continue;
        }
        let mut affected: Vec<String> = Vec::new();
        let mut affected_names: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for c in repos {
            if c.archived || c.config.is_off(repo_id) {
                continue;
            }
            if let Some(entry) = affected_fn(c) {
                affected.push(entry);
                affected_names.insert(c.name.clone());
            }
        }
        if !affected.is_empty() {
            outcome.summary = format!("{} ({} affected)", outcome.summary, affected.len());
            suppressions
                .entry(*repo_id)
                .or_default()
                .extend(affected_names);
            affected_by_check.insert(*org_name, affected);
        }
    }
    (affected_by_check, suppressions)
}

fn immutable_branch_fails(state: &crate::checks::repos::context::BranchProtectionState) -> bool {
    use crate::checks::repos::context::BranchProtectionState;
    match state {
        BranchProtectionState::Protected {
            allow_force_pushes,
            allow_deletions,
            ..
        } => *allow_force_pushes || *allow_deletions,
        BranchProtectionState::Unprotected => true,
        _ => false,
    }
}

pub async fn fetch_repo_contexts(
    client: &Client,
    account: &str,
    kind: AccountKind,
) -> Result<Vec<RepoContext>> {
    let listing_path = match kind {
        AccountKind::Organization => format!("/orgs/{account}/repos?type=all"),
        AccountKind::User => format!("/users/{account}/repos"),
    };

    let listings: Vec<RepoListing> = match client.get_paginated(&listing_path).await? {
        Fetch::Ok(v) => v,
        Fetch::Forbidden => {
            bail!("no permission to list repositories for `{account}` — check your token scopes")
        }
        Fetch::NotFound => Vec::new(),
    };
    let listings: Vec<RepoListing> = listings
        .into_iter()
        .filter(|r| !r.fork && !r.archived)
        .collect();
    fetch_contexts(client, account, listings).await
}

pub async fn fetch_single_repo_context(
    client: &Client,
    owner: &str,
    repo: &str,
) -> Result<Vec<RepoContext>> {
    let listing: RepoListing = match client
        .get_json::<RepoListing>(&format!("/repos/{owner}/{repo}"))
        .await?
    {
        Fetch::Ok(v) => v,
        Fetch::Forbidden => {
            bail!("no permission to read `{owner}/{repo}` — check your token scopes")
        }
        Fetch::NotFound => bail!("no repository named `{owner}/{repo}` was found"),
    };
    fetch_contexts(client, owner, vec![listing]).await
}

async fn fetch_contexts(
    client: &Client,
    account: &str,
    listings: Vec<RepoListing>,
) -> Result<Vec<RepoContext>> {
    let total = listings.len();
    panel::progress(&format!("scanning {total} repositories"));

    let mut contexts: Vec<RepoContext> = stream::iter(listings)
        .map(|listing| async move { RepoContext::fetch(client, account, listing).await })
        .buffer_unordered(CONCURRENCY)
        .filter_map(|r| async move {
            match r {
                Ok(c) => Some(c),
                Err(e) => {
                    eprintln!("  {} {e}", "!".red());
                    None
                }
            }
        })
        .collect()
        .await;

    contexts.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(contexts)
}

pub fn render_repo_checks(
    contexts: &[RepoContext],
    suppressions: Option<&Suppressions>,
    prepended: Vec<Finding>,
    verbose: bool,
) {
    panel::finish_progress("repositories");

    let columns: &[RepoCheck] = &[
        (
            "protected_release_branches",
            protected_release_branches::COLUMN,
            protected_release_branches::DESCRIPTION,
            protected_release_branches::HOW_TO_FIX,
            protected_release_branches::WHY_ENABLE,
            protected_release_branches::check,
        ),
        (
            "signed_commits",
            signed_commits::COLUMN,
            signed_commits::DESCRIPTION,
            signed_commits::HOW_TO_FIX,
            signed_commits::WHY_ENABLE,
            signed_commits::check,
        ),
        (
            "pr_reviews",
            pr_reviews::COLUMN,
            pr_reviews::DESCRIPTION,
            pr_reviews::HOW_TO_FIX,
            pr_reviews::WHY_ENABLE,
            pr_reviews::check,
        ),
        (
            "workflow_token",
            workflow_token::COLUMN,
            workflow_token::DESCRIPTION,
            workflow_token::HOW_TO_FIX,
            workflow_token::WHY_ENABLE,
            workflow_token::check,
        ),
        (
            "secret_scanning",
            secret_scanning::COLUMN,
            secret_scanning::DESCRIPTION,
            secret_scanning::HOW_TO_FIX,
            secret_scanning::WHY_ENABLE,
            secret_scanning::check,
        ),
        (
            "push_protection",
            push_protection::COLUMN,
            push_protection::DESCRIPTION,
            push_protection::HOW_TO_FIX,
            push_protection::WHY_ENABLE,
            push_protection::check,
        ),
        (
            "dependabot_alerts",
            dependabot_alerts::COLUMN,
            dependabot_alerts::DESCRIPTION,
            dependabot_alerts::HOW_TO_FIX,
            dependabot_alerts::WHY_ENABLE,
            dependabot_alerts::check,
        ),
        (
            "admin_enforcement",
            admin_enforcement::COLUMN,
            admin_enforcement::DESCRIPTION,
            admin_enforcement::HOW_TO_FIX,
            admin_enforcement::WHY_ENABLE,
            admin_enforcement::check,
        ),
        (
            "immutable_branch",
            immutable_branch::COLUMN,
            immutable_branch::DESCRIPTION,
            immutable_branch::HOW_TO_FIX,
            immutable_branch::WHY_ENABLE,
            immutable_branch::check,
        ),
        (
            "linear_history",
            linear_history::COLUMN,
            linear_history::DESCRIPTION,
            linear_history::HOW_TO_FIX,
            linear_history::WHY_ENABLE,
            linear_history::check,
        ),
        (
            "pinned_actions",
            pinned_actions::COLUMN,
            pinned_actions::DESCRIPTION,
            pinned_actions::HOW_TO_FIX,
            pinned_actions::WHY_ENABLE,
            pinned_actions::check,
        ),
        (
            "pull_request_target",
            pull_request_target::COLUMN,
            pull_request_target::DESCRIPTION,
            pull_request_target::HOW_TO_FIX,
            pull_request_target::WHY_ENABLE,
            pull_request_target::check,
        ),
        (
            "workflow_permissions",
            workflow_permissions::COLUMN,
            workflow_permissions::DESCRIPTION,
            workflow_permissions::HOW_TO_FIX,
            workflow_permissions::WHY_ENABLE,
            workflow_permissions::check,
        ),
        (
            "webhooks",
            webhooks::COLUMN,
            webhooks::DESCRIPTION,
            webhooks::HOW_TO_FIX,
            webhooks::WHY_ENABLE,
            webhooks::check,
        ),
        (
            "direct_collaborators",
            direct_collaborators::COLUMN,
            direct_collaborators::DESCRIPTION,
            direct_collaborators::HOW_TO_FIX,
            direct_collaborators::WHY_ENABLE,
            direct_collaborators::check,
        ),
        (
            "security_md",
            security_md::COLUMN,
            security_md::DESCRIPTION,
            security_md::HOW_TO_FIX,
            security_md::WHY_ENABLE,
            security_md::check,
        ),
        (
            "dependabot_config",
            dependabot_config::COLUMN,
            dependabot_config::DESCRIPTION,
            dependabot_config::HOW_TO_FIX,
            dependabot_config::WHY_ENABLE,
            dependabot_config::check,
        ),
    ];

    let active_total = contexts.iter().filter(|c| !c.archived).count();

    let mut repo_findings: Vec<Finding> = Vec::new();
    for (id, label, _desc, how_to_fix, why_enable, run) in columns {
        let mut fail_repos: Vec<String> = Vec::new();
        let mut unknown_repos: Vec<String> = Vec::new();
        for ctx in contexts {
            if ctx.archived || ctx.config.is_off(id) {
                continue;
            }
            let suppressed = suppressions
                .map(|s| s.get(id).is_some_and(|set| set.contains(&ctx.name)))
                .unwrap_or(false);
            let outcome = run(ctx);
            match outcome.status {
                Status::Fail if !suppressed => fail_repos.push(ctx.name.clone()),
                Status::Skipped if outcome.summary == "?" => unknown_repos.push(ctx.name.clone()),
                _ => {}
            }
        }
        let label_owned = label.replace('_', " ");
        let title = label_owned.as_str().to_uppercase_first();
        if !fail_repos.is_empty() {
            repo_findings.push(Finding {
                title: title.clone(),
                how_to_fix,
                why_enable,
                severity: Status::Fail,
                affected_count: fail_repos.len(),
                affected_list: Some(fail_repos),
            });
        }
        if !unknown_repos.is_empty() {
            repo_findings.push(Finding {
                title,
                how_to_fix,
                why_enable,
                severity: Status::Skipped,
                affected_count: unknown_repos.len(),
                affected_list: Some(unknown_repos),
            });
        }
    }

    let mut combined: Vec<Finding> = prepended;
    combined.append(&mut repo_findings);

    combined.sort_by(|a, b| match (a.severity, b.severity) {
        (Status::Fail, Status::Fail)
        | (Status::Warn, Status::Warn)
        | (Status::Skipped, Status::Skipped) => b.affected_count.cmp(&a.affected_count),
        (Status::Fail, _) => std::cmp::Ordering::Less,
        (_, Status::Fail) => std::cmp::Ordering::Greater,
        (Status::Warn, _) => std::cmp::Ordering::Less,
        (_, Status::Warn) => std::cmp::Ordering::Greater,
        _ => std::cmp::Ordering::Equal,
    });

    render_findings_panel(&combined, active_total, verbose);
}
