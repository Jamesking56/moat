use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "moat", version, about = "Supply-chain security auditor for GitHub organizations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Audit {
        account: String,

        #[arg(long, value_enum)]
        only: Option<Only>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Only {
    Org,
    Repos,
}
