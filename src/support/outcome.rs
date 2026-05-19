use owo_colors::OwoColorize;

pub struct CheckOutcome {
    pub status: Status,
    pub summary: String,
    pub items: Vec<String>,
    pub failing_branches: Vec<String>,
    pub skip_reason: Option<SkipReason>,
}

/// Why a check returned `Skipped`. Drives how the runner buckets the skip in
/// summary breakdowns and footer notes — plan-gated skips are reported as
/// private-repo exclusions; no-data skips use the supplied label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Feature is gated by the repo's plan (typically a private repo on Free).
    PlanGated,
    /// The repo had no data for the check to evaluate (e.g. no workflows).
    /// The label is rendered verbatim in the summary breakdown.
    NoData(&'static str),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Skipped,
}

impl CheckOutcome {
    pub fn pass(summary: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            summary: summary.into(),
            items: Vec::new(),
            failing_branches: Vec::new(),
            skip_reason: None,
        }
    }
    pub fn fail(summary: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            summary: summary.into(),
            items: Vec::new(),
            failing_branches: Vec::new(),
            skip_reason: None,
        }
    }
    pub fn warn(summary: impl Into<String>) -> Self {
        Self {
            status: Status::Warn,
            summary: summary.into(),
            items: Vec::new(),
            failing_branches: Vec::new(),
            skip_reason: None,
        }
    }
    pub fn skipped(summary: impl Into<String>) -> Self {
        Self {
            status: Status::Skipped,
            summary: summary.into(),
            items: Vec::new(),
            failing_branches: Vec::new(),
            skip_reason: None,
        }
    }
    /// Skipped because the feature is gated by the org/repo plan.
    pub fn skipped_plan_gated(summary: impl Into<String>) -> Self {
        let mut o = Self::skipped(summary);
        o.skip_reason = Some(SkipReason::PlanGated);
        o
    }
    /// Skipped because the repo has no data for this check. The label is shown
    /// verbatim in the breakdown (e.g. "repos, no workflows").
    pub fn skipped_no_data(summary: impl Into<String>, label: &'static str) -> Self {
        let mut o = Self::skipped(summary);
        o.skip_reason = Some(SkipReason::NoData(label));
        o
    }
    pub fn with_items(mut self, items: Vec<String>) -> Self {
        self.items = items;
        self
    }
    pub fn with_failing_branches(mut self, branches: Vec<String>) -> Self {
        self.failing_branches = branches;
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
            Status::Fail => "✕",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_set_status_and_summary() {
        assert_eq!(CheckOutcome::pass("ok").status, Status::Pass);
        assert_eq!(CheckOutcome::pass("ok").summary, "ok");
        assert_eq!(CheckOutcome::fail("bad").status, Status::Fail);
        assert_eq!(CheckOutcome::warn("hm").status, Status::Warn);
        assert_eq!(CheckOutcome::skipped("n/a").status, Status::Skipped);
    }

    #[test]
    fn with_items_attaches_items() {
        let o = CheckOutcome::fail("x").with_items(vec!["a".into(), "b".into()]);
        assert_eq!(o.items, vec!["a", "b"]);
    }

    #[test]
    fn badge_is_distinct_per_status() {
        assert_eq!(Status::Pass.badge(), "✓");
        assert_eq!(Status::Fail.badge(), "✕");
        assert_eq!(Status::Warn.badge(), "!");
        assert_eq!(Status::Skipped.badge(), "·");
    }

    #[test]
    fn colored_summary_contains_summary_text() {
        let o = CheckOutcome::pass("required");
        assert!(o.colored_summary().contains("required"));
    }

    #[test]
    fn colored_badge_contains_glyph() {
        assert!(Status::Pass.colored_badge().contains('✓'));
        assert!(Status::Fail.colored_badge().contains('✕'));
    }
}
