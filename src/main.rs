mod checks;
mod cli;
mod runner;
mod support;

use anyhow::Result;
use clap::Parser;
use owo_colors::OwoColorize;
use runner::AccountKind;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let token = support::github::resolve_token()?;
    let client = support::github::Client::new(token)?;

    match cli.command {
        cli::Command::Audit { account, only } => {
            let kind = runner::detect_account(&client, &account).await?;
            runner::print_header(&account, kind);

            let do_org = matches!(only, None | Some(cli::Only::Org));
            let do_repos = matches!(only, None | Some(cli::Only::Repos));

            if do_org {
                match kind {
                    AccountKind::Organization => runner::run_org_checks(&client, &account).await?,
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
                runner::run_repo_checks(&client, &account, kind).await?;
            }
        }
    }

    Ok(())
}
