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
        cli::Command::Audit { account, verbose } => {
            if let Some((owner, repo)) = account.split_once('/') {
                if owner.is_empty() || repo.is_empty() || repo.contains('/') {
                    anyhow::bail!(
                        "invalid target `{account}` — expected `owner/repo` or `account`"
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
                let results = runner::run_checks(&ctx);
                let active_total = contexts.iter().filter(|c| !c.archived).count();
                runner::render_checks_panel(&results, None, active_total, verbose);
                runner::render_posture_panel(&results);
            } else {
                let kind = runner::detect_account(&client, &account).await?;
                runner::print_header(&account, kind);

                let do_org = matches!(kind, AccountKind::Organization);

                let listings = runner::list_repos(&client, &account, kind).await?;

                let mut total_ticks = 1 + runner::REPO_TICKS * listings.len();
                if do_org {
                    total_ticks += runner::ORG_TICKS;
                }
                support::panel::bump_progress_total(total_ticks);

                let org_ctx = if do_org {
                    Some(runner::fetch_org_context(&client, &account).await?)
                } else {
                    None
                };

                let repo_contexts =
                    runner::fetch_repo_contexts_from(&client, &account, listings).await?;

                support::panel::finish_progress(match kind {
                    AccountKind::Organization => "organization",
                    AccountKind::User => "user",
                });

                let ctx = CheckContext {
                    org: org_ctx.as_ref(),
                    repos: &repo_contexts,
                };
                let results = runner::run_checks(&ctx);
                let active_total = repo_contexts.iter().filter(|c| !c.archived).count();
                runner::render_checks_panel(&results, org_ctx.as_ref(), active_total, verbose);
                runner::render_posture_panel(&results);
            }
        }
    }

    Ok(())
}
