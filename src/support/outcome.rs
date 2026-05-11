use owo_colors::OwoColorize;

pub struct CheckOutcome {
    pub status: Status,
    pub summary: String,
    pub items: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Skipped,
}

impl CheckOutcome {
    pub fn pass(summary: impl Into<String>) -> Self {
        Self { status: Status::Pass, summary: summary.into(), items: Vec::new() }
    }
    pub fn fail(summary: impl Into<String>) -> Self {
        Self { status: Status::Fail, summary: summary.into(), items: Vec::new() }
    }
    pub fn warn(summary: impl Into<String>) -> Self {
        Self { status: Status::Warn, summary: summary.into(), items: Vec::new() }
    }
    pub fn skipped(summary: impl Into<String>) -> Self {
        Self { status: Status::Skipped, summary: summary.into(), items: Vec::new() }
    }
    pub fn with_items(mut self, items: Vec<String>) -> Self {
        self.items = items;
        self
    }

    pub fn colored_summary(&self) -> String {
        match self.status {
            Status::Pass => self.summary.green().to_string(),
            Status::Fail => self.summary.red().to_string(),
            Status::Warn => self.summary.yellow().to_string(),
            Status::Skipped => self.summary.dimmed().to_string(),
        }
    }
}

impl Status {
    pub fn badge(self) -> &'static str {
        match self {
            Status::Pass => "✓",
            Status::Fail => "✗",
            Status::Warn => "!",
            Status::Skipped => "·",
        }
    }

    pub fn colored_badge(self) -> String {
        match self {
            Status::Pass => self.badge().green().to_string(),
            Status::Fail => self.badge().red().bold().to_string(),
            Status::Warn => self.badge().yellow().to_string(),
            Status::Skipped => self.badge().dimmed().to_string(),
        }
    }
}
