use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "moat",
    version,
    about = "Supply-chain security auditor for GitHub organizations"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Audit {
        account: String,

        /// Display all collaborators and members instead of truncating the list.
        #[arg(short, long)]
        verbose: bool,
    },
}
