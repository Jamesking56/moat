use anyhow::Result;
use clap::Parser;
use moat::runner::{self, AccountKind, CheckContext};
use moat::{cli, support};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let token = support::github::resolve_token()?;
    let client = support::github::Client::new(token)?;

    match cli.command {
        cli::Command::Audit {
            account,
            only,
            verbose,
        } => {
            if let Some((owner, repo)) = account.split_once('/') {
                if owner.is_empty() || repo.is_empty() || repo.contains('/') {
                    anyhow::bail!(
                        "invalid target `{account}` — expected `owner/repo` or `account`"
                    );
                }
                if matches!(only, Some(cli::Only::Org)) {
                    anyhow::bail!(
                        "`--only org` is not supported when auditing a single repository"
                    );
                }
                runner::print_repo_header(owner, repo);
                support::panel::bump_progress_total(1 + runner::REPO_TICKS);
                let contexts = runner::fetch_single_repo_context(&client, owner, repo).await?;
                support::panel::finish_progress("repository");

                let ctx = CheckContext {
                    org: None,
                    repos: &contexts,
                };
                let results = runner::run_checks(&ctx, only);
                let active_total = contexts.iter().filter(|c| !c.archived).count();
                runner::render_checks_panel(&results, None, active_total, verbose);
                runner::render_posture_panel(&results);
            } else {
                let kind = runner::detect_account(&client, &account).await?;
                runner::print_header(&account, kind);

                let do_org = matches!(only, None | Some(cli::Only::Org))
                    && matches!(kind, AccountKind::Organization);
                let do_repos = matches!(only, None | Some(cli::Only::Repos));

                let listings = if do_repos {
                    Some(runner::list_repos(&client, &account, kind).await?)
                } else {
                    None
                };

                let mut total_ticks = 0;
                if do_org {
                    total_ticks += runner::ORG_TICKS;
                }
                if let Some(l) = &listings {
                    total_ticks += 1 + runner::REPO_TICKS * l.len();
                }
                support::panel::bump_progress_total(total_ticks);

                let org_ctx = if do_org {
                    Some(runner::fetch_org_context(&client, &account).await?)
                } else {
                    None
                };

                let repo_contexts = if let Some(l) = listings {
                    Some(runner::fetch_repo_contexts_from(&client, &account, l).await?)
                } else {
                    None
                };

                let empty: Vec<_> = Vec::new();
                let repos_slice = repo_contexts.as_deref().unwrap_or(&empty);
                support::panel::finish_progress(match kind {
                    AccountKind::Organization => "organization",
                    AccountKind::User => "user",
                });

                let ctx = CheckContext {
                    org: org_ctx.as_ref(),
                    repos: repos_slice,
                };
                let results = runner::run_checks(&ctx, only);
                let active_total = repos_slice.iter().filter(|c| !c.archived).count();
                runner::render_checks_panel(&results, org_ctx.as_ref(), active_total, verbose);
                runner::render_posture_panel(&results);
            }
        }
    }

    Ok(())
}
