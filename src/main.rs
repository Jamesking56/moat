use anyhow::Result;
use clap::Parser;
use moat::runner::{self, AccountKind, CheckContext};
use moat::support::panel;
use moat::support::report::Report;
use moat::{cli, support};

#[tokio::main]
async fn main() {
    match run().await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{} {e}", panel::danger_bold("Error:"));
            std::process::exit(1);
        }
    }
}

async fn run() -> Result<i32> {
    let cli = cli::Cli::parse();
    panel::init_theme(cli.theme.into());
    let token = support::github::resolve_token()?;
    let client = support::github::Client::new(token)?;

    let cli::Cli {
        account,
        verbose,
        theme: _,
        format,
    } = cli;

    let pretty = matches!(format, cli::Format::Pretty);

    if let Some((owner, repo)) = account.split_once('/') {
        if owner.is_empty() || repo.is_empty() || repo.contains('/') {
            anyhow::bail!("Invalid target `{account}` — expected `owner/repo` or `account`");
        }
        let listing = runner::ensure_viewer_can_audit_repo(&client, owner, repo).await?;
        if pretty {
            runner::print_repo_header(owner, repo);
            support::panel::bump_progress_total(1 + runner::REPO_TICKS);
        }
        let contexts = runner::fetch_single_repo_context(&client, owner, listing).await?;
        if pretty {
            support::panel::finish_progress("Repository");
        }

        let ctx = CheckContext {
            org: None,
            repos: &contexts,
        };
        let results = runner::run_checks(&ctx);
        let active_total = contexts.iter().filter(|c| !c.archived).count();
        if pretty {
            runner::render_checks_panel(&results, None, owner, active_total, verbose);
            runner::render_posture_panel(&results);
        } else {
            emit_report(format, &account, "repository", &results)?;
        }
        Ok(runner::exit_code(&results))
    } else {
        let kind = runner::ensure_viewer_can_audit_account(&client, &account).await?;
        if pretty {
            runner::print_header(&account, kind);
        }

        let do_org = matches!(kind, AccountKind::Organization);

        let listings = runner::list_repos(&client, &account, kind).await?;

        if pretty {
            let mut total_ticks = 1 + runner::REPO_TICKS * listings.len();
            if do_org {
                total_ticks += runner::ORG_TICKS;
            }
            support::panel::bump_progress_total(total_ticks);
        }

        let org_ctx = if do_org {
            Some(runner::fetch_org_context(&client, &account).await?)
        } else {
            None
        };

        let repo_contexts = runner::fetch_repo_contexts_from(&client, &account, listings).await?;

        if pretty {
            support::panel::finish_progress(match kind {
                AccountKind::Organization => "Organization",
                AccountKind::User => "User",
            });
        }

        let ctx = CheckContext {
            org: org_ctx.as_ref(),
            repos: &repo_contexts,
        };
        let results = runner::run_checks(&ctx);
        let active_total = repo_contexts.iter().filter(|c| !c.archived).count();
        if pretty {
            runner::render_checks_panel(
                &results,
                org_ctx.as_ref(),
                &account,
                active_total,
                verbose,
            );
            runner::render_posture_panel(&results);
        } else {
            let kind_str = match kind {
                AccountKind::Organization => "organization",
                AccountKind::User => "user",
            };
            emit_report(format, &account, kind_str, &results)?;
        }
        Ok(runner::exit_code(&results))
    }
}

fn emit_report(
    format: cli::Format,
    account: &str,
    account_kind: &str,
    results: &[moat::runner::CheckResult],
) -> Result<()> {
    let report = Report::from_results(account, account_kind, results);
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    match format {
        cli::Format::Json => report.write_json(&mut handle)?,
        cli::Format::Markdown => report.write_markdown(&mut handle)?,
        cli::Format::Pretty => unreachable!("pretty handled on the caller side"),
    }
    Ok(())
}
