use anyhow::Result;
use clap::Parser;
use moat::runner::AccountKind;
use moat::{cli, runner, support};
use owo_colors::OwoColorize;

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
                runner::run_single_repo_check(&client, owner, repo, verbose).await?;
            } else {
                let kind = runner::detect_account(&client, &account).await?;
                runner::print_header(&account, kind);

                let do_org = matches!(only, None | Some(cli::Only::Org));
                let do_repos = matches!(only, None | Some(cli::Only::Repos));

                if do_org {
                    match kind {
                        AccountKind::Organization => {
                            runner::run_org_checks(&client, &account, verbose).await?
                        }
                        AccountKind::User => {
                            println!("  {}", "ORGANIZATION".bold());
                            println!(
                                "    {}",
                                "skipped — user accounts have no org-level settings".dimmed()
                            );
                            println!();
                        }
                    }
                }
                if do_repos {
                    runner::run_repo_checks(&client, &account, kind, verbose).await?;
                }
            }
        }
    }

    Ok(())
}
