use crate::checks::orgs::{
    OrgContext, context::MemberList, default_repo_permission,
    dependabot_alerts as org_dependabot_alerts, fork_pr_contributor_approval, members_without_2fa,
    push_protection as org_push_protection, release_immutability,
    secret_scanning as org_secret_scanning, two_factor_required,
    workflow_token as org_workflow_token,
};
use crate::checks::repos::{
    RepoContext, admin_enforcement, branch_protection, context::RepoListing, dependabot_alerts,
    dependabot_config, direct_collaborators, immutable_branch, linear_history, pinned_actions,
    pr_reviews,
    pull_request_target, push_protection, secret_scanning, security_md, signed_commits, webhooks,
    workflow_permissions, workflow_token,
};
use crate::support::github::{Client, Fetch};
use crate::support::outcome::{CheckOutcome, Status};
use crate::support::render::{self, Cell};
use anyhow::{Result, anyhow, bail};
use futures::stream::{self, StreamExt};
use owo_colors::OwoColorize;
use serde::Deserialize;

const CONCURRENCY: usize = 12;
const MAX_REPO_NAME: usize = 40;

type RepoCheck = (
    &'static str,
    &'static str,
    &'static str,
    fn(&RepoContext) -> CheckOutcome,
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
    println!();
    println!(
        "  {}   {}{}{} {} {}",
        "moat".bold().cyan(),
        owner.bold(),
        "/".bright_black(),
        repo.bold(),
        "·".bright_black(),
        "repository".dimmed()
    );
    println!();
}

pub fn print_header(account: &str, kind: AccountKind) {
    let kind_long = match kind {
        AccountKind::Organization => "organization",
        AccountKind::User => "user",
    };
    println!();
    println!(
        "  {}   {} {} {}",
        "moat".bold().cyan(),
        account.bold(),
        "·".bright_black(),
        kind_long.dimmed()
    );
    println!();
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
    eprintln!(
        "  {} fetching {}",
        "→".bright_black(),
        "organization".bold()
    );
    OrgContext::fetch(client, org).await
}

pub fn render_org_checks(ctx: &OrgContext, verbose: bool) {
    let results = [
        (
            two_factor_required::NAME,
            two_factor_required::DESCRIPTION,
            two_factor_required::check(ctx),
        ),
        (
            members_without_2fa::NAME,
            members_without_2fa::DESCRIPTION,
            members_without_2fa::check(ctx),
        ),
        (
            default_repo_permission::NAME,
            default_repo_permission::DESCRIPTION,
            default_repo_permission::check(ctx),
        ),
        (
            release_immutability::NAME,
            release_immutability::DESCRIPTION,
            release_immutability::check(ctx),
        ),
        (
            fork_pr_contributor_approval::NAME,
            fork_pr_contributor_approval::DESCRIPTION,
            fork_pr_contributor_approval::check(ctx),
        ),
        (
            org_workflow_token::NAME,
            org_workflow_token::DESCRIPTION,
            org_workflow_token::check(ctx),
        ),
        (
            org_secret_scanning::NAME,
            org_secret_scanning::DESCRIPTION,
            org_secret_scanning::check(ctx),
        ),
        (
            org_push_protection::NAME,
            org_push_protection::DESCRIPTION,
            org_push_protection::check(ctx),
        ),
        (
            org_dependabot_alerts::NAME,
            org_dependabot_alerts::DESCRIPTION,
            org_dependabot_alerts::check(ctx),
        ),
    ];

    let passing = results
        .iter()
        .filter(|(_, _, o)| o.status == Status::Pass)
        .count();
    println!(
        "  {}   {}{} {} {} {}",
        "ORGANIZATION".bold(),
        results.len().to_string().bold(),
        " checks".dimmed(),
        "·".bright_black(),
        passing.to_string().bold(),
        "passing".dimmed(),
    );
    println!();
    let name_width = results
        .iter()
        .map(|(n, _, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    for (name, _, outcome) in &results {
        let pad = " ".repeat(name_width.saturating_sub(name.chars().count()));
        println!(
            "    {}  {}{}  {}",
            outcome.status.colored_badge(),
            name,
            pad,
            outcome.colored_summary()
        );
        render_items(&outcome.items, name_width + 9, verbose);
    }
    println!();

    let inventory: &[(&str, &MemberList)] = &[
        ("Outside collaborators", &ctx.outside_collaborators),
        ("Org admins", &ctx.admins),
    ];
    let inv_width = inventory
        .iter()
        .map(|(n, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    println!("  {}", "INVENTORY".bold());
    for (name, list) in inventory {
        let pad = " ".repeat(inv_width.saturating_sub(name.chars().count()));
        let (summary, items): (String, &[String]) = match list {
            MemberList::NoPermission => ("(requires org admin token)".to_string(), &[]),
            MemberList::Ok(v) if v.is_empty() => ("none".to_string(), &[]),
            MemberList::Ok(v) => (v.len().to_string(), v.as_slice()),
        };
        println!("    {}{}  {}", name.bold(), pad, summary.dimmed());
        render_items(items, inv_width + 6, verbose);
    }
    println!();

    println!("  {}", "CHECKS".bold());
    for (name, description, _) in &results {
        let pad = " ".repeat(name_width.saturating_sub(name.chars().count()));
        println!("    {}{}  {}", name.bold(), pad, description.dimmed());
    }
    println!();

    println!(
        "    {}  {} pass  {}  {} fail  {}  {} warning  {}  {} skipped / no permission",
        "LEGEND".dimmed(),
        "✓".green(),
        "·".bright_black(),
        "✗".red(),
        "·".bright_black(),
        "!".yellow(),
        "·".bright_black(),
        "·".dimmed(),
    );
    println!();
}

fn render_items(items: &[String], indent: usize, verbose: bool) {
    if items.is_empty() {
        return;
    }
    const PREVIEW: usize = 5;
    let pad = " ".repeat(indent);
    if verbose || items.len() <= PREVIEW + 1 {
        for item in items {
            println!("{pad}{} {}", "·".bright_black(), item.dimmed());
        }
    } else {
        let shown: Vec<&str> = items.iter().take(PREVIEW).map(String::as_str).collect();
        let rest = items.len() - PREVIEW;
        println!(
            "{pad}{} {}{}",
            "·".bright_black(),
            shown.join(", ").dimmed(),
            format!("  +{rest} more").bright_black()
        );
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
    eprintln!(
        "  {} scanning {} repositories",
        "→".bright_black(),
        total.to_string().bold()
    );

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

pub fn render_repo_checks(contexts: &[RepoContext], _verbose: bool) {
    let total = contexts.len();

    let columns: &[RepoCheck] = &[
        (
            "branch_protection",
            branch_protection::COLUMN,
            branch_protection::DESCRIPTION,
            branch_protection::check,
        ),
        (
            "signed_commits",
            signed_commits::COLUMN,
            signed_commits::DESCRIPTION,
            signed_commits::check,
        ),
        (
            "pr_reviews",
            pr_reviews::COLUMN,
            pr_reviews::DESCRIPTION,
            pr_reviews::check,
        ),
        (
            "workflow_token",
            workflow_token::COLUMN,
            workflow_token::DESCRIPTION,
            workflow_token::check,
        ),
        (
            "secret_scanning",
            secret_scanning::COLUMN,
            secret_scanning::DESCRIPTION,
            secret_scanning::check,
        ),
        (
            "push_protection",
            push_protection::COLUMN,
            push_protection::DESCRIPTION,
            push_protection::check,
        ),
        (
            "dependabot_alerts",
            dependabot_alerts::COLUMN,
            dependabot_alerts::DESCRIPTION,
            dependabot_alerts::check,
        ),
        (
            "admin_enforcement",
            admin_enforcement::COLUMN,
            admin_enforcement::DESCRIPTION,
            admin_enforcement::check,
        ),
        (
            "immutable_branch",
            immutable_branch::COLUMN,
            immutable_branch::DESCRIPTION,
            immutable_branch::check,
        ),
        (
            "linear_history",
            linear_history::COLUMN,
            linear_history::DESCRIPTION,
            linear_history::check,
        ),
        (
            "pinned_actions",
            pinned_actions::COLUMN,
            pinned_actions::DESCRIPTION,
            pinned_actions::check,
        ),
        (
            "pull_request_target",
            pull_request_target::COLUMN,
            pull_request_target::DESCRIPTION,
            pull_request_target::check,
        ),
        (
            "workflow_permissions",
            workflow_permissions::COLUMN,
            workflow_permissions::DESCRIPTION,
            workflow_permissions::check,
        ),
        (
            "webhooks",
            webhooks::COLUMN,
            webhooks::DESCRIPTION,
            webhooks::check,
        ),
        (
            "direct_collaborators",
            direct_collaborators::COLUMN,
            direct_collaborators::DESCRIPTION,
            direct_collaborators::check,
        ),
        (
            "security_md",
            security_md::COLUMN,
            security_md::DESCRIPTION,
            security_md::check,
        ),
        (
            "dependabot_config",
            dependabot_config::COLUMN,
            dependabot_config::DESCRIPTION,
            dependabot_config::check,
        ),
    ];

    let headers: Vec<&str> = ["repo", "visibility"]
        .into_iter()
        .chain(columns.iter().map(|(_, name, _, _)| *name))
        .collect();

    let mut rows: Vec<Vec<Cell>> = Vec::with_capacity(contexts.len());
    let mut totals = vec![0usize; columns.len()];
    let mut active = 0usize;
    let mut total_pass = 0usize;
    let mut total_fail = 0usize;

    for ctx in contexts {
        let truncated = render::truncate(&ctx.name, MAX_REPO_NAME);
        let name_cell = if ctx.archived {
            let visible = format!("{truncated} (archived)");
            let rendered = visible.dimmed().to_string();
            Cell::styled(visible, rendered)
        } else {
            Cell::plain(truncated)
        };

        let mut row = Vec::with_capacity(columns.len() + 2);
        row.push(name_cell);

        let visibility = if ctx.private { "private" } else { "public" };
        row.push(Cell::styled(
            visibility.to_string(),
            visibility.dimmed().to_string(),
        ));

        for (i, (id, _, _, run)) in columns.iter().enumerate() {
            let (outcome, disabled) = if ctx.config.is_off(id) {
                (CheckOutcome::skipped("off"), true)
            } else {
                (run(ctx), false)
            };
            if !ctx.archived && !disabled {
                match outcome.status {
                    Status::Fail => {
                        totals[i] += 1;
                        total_fail += 1;
                    }
                    Status::Pass => {
                        total_pass += 1;
                    }
                    _ => {}
                }
            }
            let rendered = if ctx.archived || disabled {
                outcome.summary.dimmed().to_string()
            } else {
                outcome.colored_summary()
            };
            row.push(Cell::styled(outcome.summary.clone(), rendered));
        }

        if !ctx.archived {
            active += 1;
        }
        rows.push(row);
    }

    let total_issues: usize = totals.iter().sum();

    println!(
        "  {}   {}{} {} {} {}",
        "REPOSITORIES".bold(),
        total.to_string().bold(),
        " total".dimmed(),
        "·".bright_black(),
        active.to_string().bold(),
        "active".dimmed()
    );
    println!();
    render::render(&headers, &rows);
    println!();

    let column_width = columns
        .iter()
        .map(|(_, n, _, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    println!("  {}", "COLUMNS".bold());
    for (_, name, description, _) in columns {
        let pad = " ".repeat(column_width.saturating_sub(name.chars().count()));
        println!("    {}{}  {}", name.bold(), pad, description.dimmed());
    }
    println!();

    println!(
        "    {}  {} pass  {}  {} fail  {}  {} not applicable  {}  {} unknown / no permission",
        "LEGEND".dimmed(),
        "✓".green(),
        "·".bright_black(),
        "✗".red(),
        "·".bright_black(),
        "—".bright_black(),
        "·".bright_black(),
        "?".yellow(),
    );
    println!();

    let verdict = if total_issues == 0 {
        format!("{}  no issues", "✓".green().bold())
    } else {
        format!(
            "{}  {} {}",
            "✗".red().bold(),
            total_issues.to_string().bold().red(),
            "issues across active repositories".dimmed()
        )
    };
    println!("  {}", "SUMMARY".bold());
    println!("    {verdict}");

    let parts: Vec<String> = columns
        .iter()
        .zip(totals.iter())
        .map(|((_, name, _, _), failures)| {
            let count = if *failures == 0 {
                failures.to_string().dimmed().to_string()
            } else {
                failures.to_string().red().bold().to_string()
            };
            format!("{} {count}", name.dimmed())
        })
        .collect();
    println!("    {}", parts.join(&format!("  {}  ", "·".bright_black())));
    println!();

    let applicable = total_pass + total_fail;
    let score = if applicable == 0 {
        100
    } else {
        (total_pass * 100) / applicable
    };
    let score_str = format!("{score}/100");
    let colored_score = match score {
        90..=100 => score_str.green().bold().to_string(),
        70..=89 => score_str.yellow().bold().to_string(),
        _ => score_str.red().bold().to_string(),
    };
    println!("  {}   {}", "MOAT SCORE".bold(), colored_score);
    println!();
}
