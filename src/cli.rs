use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(
    name = "moat",
    version,
    about = "Supply-chain hygiene for your GitHub organization & repositories"
)]
pub struct Cli {
    pub account: String,

    /// Display all collaborators and members instead of truncating the list.
    #[arg(short, long)]
    pub verbose: bool,

    /// Color theme. `auto` detects the terminal background via COLORFGBG.
    #[arg(long, value_enum, default_value_t = Theme::Auto)]
    pub theme: Theme,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Theme {
    #[default]
    Auto,
    Dark,
    Light,
}

impl From<Theme> for crate::support::panel::ThemeChoice {
    fn from(t: Theme) -> Self {
        match t {
            Theme::Auto => Self::Auto,
            Theme::Dark => Self::Dark,
            Theme::Light => Self::Light,
        }
    }
}
