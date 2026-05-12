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
                let contexts = runner::fetch_single_repo_context(&client, owner, repo).await?;
                runner::render_repo_checks(&contexts, None, Vec::new(), verbose);
            } else {
                let kind = runner::detect_account(&client, &account).await?;
                runner::print_header(&account, kind);

                let do_org = matches!(only, None | Some(cli::Only::Org));
                let do_repos = matches!(only, None | Some(cli::Only::Repos));

                let org_ctx = if do_org && matches!(kind, AccountKind::Organization) {
                    Some(runner::fetch_org_context(&client, &account).await?)
                } else {
                    None
                };

                let repo_contexts = if do_repos {
                    Some(runner::fetch_repo_contexts(&client, &account, kind).await?)
                } else {
                    None
                };

                let mut suppressions: Option<runner::Suppressions> = None;
                let mut org_findings: Vec<runner::Finding> = Vec::new();
                if do_org {
                    match (kind, &org_ctx) {
                        (AccountKind::Organization, Some(ctx)) => {
                            let (s, f) =
                                runner::render_org_checks(ctx, repo_contexts.as_deref(), verbose);
                            suppressions = Some(s);
                            org_findings = f;
                        }
                        (AccountKind::User, _) => {
                            println!("  {}", "ORGANIZATION".bold());
                            println!(
                                "    {}",
                                "skipped — user accounts have no org-level settings".dimmed()
                            );
                            println!();
                        }
                        _ => {}
                    }
                }
                if let Some(contexts) = repo_contexts.as_deref() {
                    runner::render_repo_checks(
                        contexts,
                        suppressions.as_ref(),
                        org_findings,
                        verbose,
                    );
                } else if !org_findings.is_empty() {
                    runner::render_findings_panel(&org_findings, 0, verbose);
                }
                if matches!(kind, AccountKind::Organization)
                    && let Some(ctx) = org_ctx.as_ref()
                {
                    runner::render_org_inventory(ctx, repo_contexts.as_deref(), verbose);
                }
            }
        }
    }

    Ok(())
}
