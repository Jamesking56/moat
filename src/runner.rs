use crate::checks::orgs::{
    OrgContext, admins, members_without_2fa, outside_collaborators, two_factor_required,
};
use crate::checks::repos::{
    RepoContext, branch_protection, context::RepoListing, dependabot_alerts, pr_reviews,
    push_protection, secret_scanning, signed_commits, workflow_token,
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

type RepoCheck = (&'static str, &'static str, fn(&RepoContext) -> CheckOutcome);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    Organization,
    User,
}

#[derive(Deserialize)]
struct AccountType {
    #[serde(rename = "type")]
    kind: String,
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
    match client.get_json::<AccountType>(&format!("/users/{name}")).await? {
        Fetch::Ok(a) if a.kind == "Organization" => Ok(AccountKind::Organization),
        Fetch::Ok(a) if a.kind == "User" => Ok(AccountKind::User),
        Fetch::Ok(a) => bail!("unexpected account type `{}` for `{name}`", a.kind),
        Fetch::Forbidden => Err(anyhow!(
            "no access to `{name}` — check your token scopes (`read:org` for private orgs)"
        )),
        Fetch::NotFound => bail!("no GitHub account named `{name}` was found."),
    }
}

pub async fn run_org_checks(client: &Client, org: &str) -> Result<()> {
    let ctx = OrgContext::fetch(client, org).await?;

    let results = [
        (two_factor_required::NAME, two_factor_required::check(&ctx)),
        (members_without_2fa::NAME, members_without_2fa::check(&ctx)),
        (outside_collaborators::NAME, outside_collaborators::check(&ctx)),
        (admins::NAME, admins::check(&ctx)),
    ];

    println!("  {}", "ORGANIZATION".bold());
    let name_width = results.iter().map(|(n, _)| n.chars().count()).max().unwrap_or(0);
    for (name, outcome) in &results {
        let pad = " ".repeat(name_width.saturating_sub(name.chars().count()));
        println!(
            "    {}  {}{}  {}",
            outcome.status.colored_badge(),
            name,
            pad,
            outcome.colored_summary()
        );
        render_items(&outcome.items, name_width + 8);
    }
    println!();
    Ok(())
}

fn render_items(items: &[String], indent: usize) {
    if items.is_empty() {
        return;
    }
    const PREVIEW: usize = 5;
    let pad = " ".repeat(indent);
    if items.len() <= PREVIEW + 1 {
        for item in items {
            println!("{pad}{} {}", "·".bright_black(), item.dimmed());
        }
    } else {
        let shown: Vec<&str> = items.iter().take(PREVIEW).map(String::as_str).collect();
        let rest = items.len() - PREVIEW;
        println!(
            "{pad}{}  {}{}",
            "·".bright_black(),
            shown.join(", ").dimmed(),
            format!("  +{rest} more").bright_black()
        );
    }
}

pub async fn run_repo_checks(client: &Client, account: &str, kind: AccountKind) -> Result<()> {
    let listing_path = match kind {
        AccountKind::Organization => format!("/orgs/{account}/repos?type=all"),
        AccountKind::User => format!("/users/{account}/repos"),
    };

    let listings: Vec<RepoListing> = match client.get_paginated(&listing_path).await? {
        Fetch::Ok(v) => v,
        Fetch::Forbidden => bail!(
            "no permission to list repositories for `{account}` — check your token scopes"
        ),
        Fetch::NotFound => Vec::new(),
    };
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

    let columns: &[RepoCheck] = &[
        (branch_protection::COLUMN, branch_protection::DESCRIPTION, branch_protection::check),
        (signed_commits::COLUMN, signed_commits::DESCRIPTION, signed_commits::check),
        (pr_reviews::COLUMN, pr_reviews::DESCRIPTION, pr_reviews::check),
        (workflow_token::COLUMN, workflow_token::DESCRIPTION, workflow_token::check),
        (secret_scanning::COLUMN, secret_scanning::DESCRIPTION, secret_scanning::check),
        (push_protection::COLUMN, push_protection::DESCRIPTION, push_protection::check),
        (dependabot_alerts::COLUMN, dependabot_alerts::DESCRIPTION, dependabot_alerts::check),
    ];

    let headers: Vec<&str> = std::iter::once("repo")
        .chain(columns.iter().map(|(name, _, _)| *name))
        .collect();

    let mut rows: Vec<Vec<Cell>> = Vec::with_capacity(contexts.len());
    let mut totals = vec![0usize; columns.len()];
    let mut active = 0usize;

    for ctx in &contexts {
        let truncated = render::truncate(&ctx.name, MAX_REPO_NAME);
        let name_cell = if ctx.archived {
            let visible = format!("{truncated} (archived)");
            let rendered = visible.dimmed().to_string();
            Cell::styled(visible, rendered)
        } else {
            Cell::plain(truncated)
        };

        let mut row = Vec::with_capacity(columns.len() + 1);
        row.push(name_cell);

        for (i, (_, _, run)) in columns.iter().enumerate() {
            let outcome = run(ctx);
            if !ctx.archived && outcome.status == Status::Fail {
                totals[i] += 1;
            }
            let rendered = if ctx.archived {
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

    let column_width = columns.iter().map(|(n, _, _)| n.chars().count()).max().unwrap_or(0);
    println!("  {}", "COLUMNS".bold());
    for (name, description, _) in columns {
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
        .map(|((name, _, _), failures)| {
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

    Ok(())
}
