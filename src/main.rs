use anyhow::Result;
use clap::Parser;
use moat::runner::{self, AccountKind, AuditTarget, CheckContext};
use moat::support::panel;
use moat::support::report::Report;
use moat::{cli, support};

#[tokio::main]
async fn main() {
    match run().await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            if let Some(auth) = e.downcast_ref::<moat::runner::AuthError>() {
                auth.render();
            } else {
                runner::render_generic_error(&format!("{e:#}"));
            }
            std::process::exit(1);
        }
    }
}

async fn run() -> Result<i32> {
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            panel::init_theme(cli::Theme::Auto.into());
            render_clap_error(&e);
            return Ok(e.exit_code());
        }
    };
    panel::init_theme(cli.theme.into());

    if cli.help {
        use clap::CommandFactory;
        let inner_width = panel::width().saturating_sub(8);
        let mut cmd = cli::Cli::command().term_width(inner_width);
        let help = cmd.render_help().to_string();
        runner::render_raw_panel("Help", &help);
        return Ok(0);
    }

    if cli.version {
        runner::render_info_panel("Version", &[format!("moat v{}", env!("CARGO_PKG_VERSION"))]);
        return Ok(0);
    }

    if cli.self_update {
        let updated = tokio::task::spawn_blocking(support::update::run_self_update)
            .await
            .ok()
            .flatten();
        let body = match updated {
            Some(v) => format!("Moat updated to v{}.", v.trim_start_matches('v')),
            None => "Moat is already up to date.".to_string(),
        };
        runner::render_info_panel("Self-update", &[body]);
        return Ok(0);
    }

    let (token, auth_source) = support::github::resolve_token()
        .map_err(|e| anyhow::Error::new(runner::format_no_token_error(&format!("{e:#}"))))?;
    let client = support::github::Client::new(token)?;
    let preflight = runner::verify_token_credentials(&client, auth_source).await?;

    let cli::Cli {
        account,
        verbose,
        self_update: _,
        help: _,
        version: _,
        theme: _,
        format,
    } = cli;
    let account = account.expect("clap guarantees account is present unless --self-update");

    let pretty = matches!(format, cli::Format::Pretty);

    let outdated_note: Option<String> = if pretty {
        let latest = tokio::task::spawn_blocking(support::update::latest_version)
            .await
            .ok()
            .flatten();
        latest
            .as_deref()
            .filter(|l| support::update::is_newer_than_current(l))
            .map(|_| "(outdated, run --self-update)".to_string())
    } else {
        None
    };
    let outdated_note = outdated_note.as_deref();

    if let Some((owner, repo)) = account.split_once('/') {
        if owner.is_empty() || repo.is_empty() || repo.contains('/') {
            anyhow::bail!("Invalid target `{account}` — expected `owner/repo` or `account`.");
        }
        let listing = runner::ensure_viewer_can_audit_repo(&client, owner, repo).await?;
        runner::verify_token_for_target(
            AuditTarget::UserOrRepo,
            &account,
            auth_source,
            preflight.clone(),
        )
        .await?;
        if pretty {
            runner::print_repo_header(owner, repo, outdated_note);
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
        let target = match kind {
            AccountKind::Organization => AuditTarget::Organization,
            AccountKind::User => AuditTarget::UserOrRepo,
        };
        runner::verify_token_for_target(target, &account, auth_source, preflight).await?;
        if pretty {
            runner::print_header(&account, kind, outdated_note);
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

fn render_clap_error(e: &clap::Error) {
    use moat::runner::{AuthError, AuthErrorLine};
    let raw = e.to_string();
    let mut lines: Vec<AuthErrorLine> = Vec::new();
    let mut first = true;
    for line in raw.lines() {
        let stripped = if first {
            first = false;
            line.trim_start_matches("error: ")
        } else {
            line
        };
        if stripped.trim().is_empty() {
            lines.push(AuthErrorLine::Blank);
        } else {
            lines.push(AuthErrorLine::Text(stripped.to_string()));
        }
    }
    while matches!(lines.last(), Some(AuthErrorLine::Blank)) {
        lines.pop();
    }
    AuthError {
        title: "Error".to_string(),
        lines,
    }
    .render();
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
