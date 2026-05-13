use clap::Parser;

#[derive(Parser)]
#[command(
    name = "moat",
    version,
    about = "Supply-chain security auditor for GitHub organizations"
)]
pub struct Cli {
    pub account: String,

    /// Display all collaborators and members instead of truncating the list.
    #[arg(short, long)]
    pub verbose: bool,
}
