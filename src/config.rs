use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

pub const FILE_NAME: &str = "moat.toml";

#[derive(Debug, Default, Clone)]
pub struct Config {
    checks: HashMap<String, CheckState>,
    release_branches: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    On,
    Off,
}

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    checks: HashMap<String, String>,
    #[serde(default)]
    release_branches: Vec<String>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(text).context("invalid moat.toml")?;
        let mut checks = HashMap::with_capacity(raw.checks.len());
        for (id, value) in raw.checks {
            let state = match value.as_str() {
                "on" => CheckState::On,
                "off" => CheckState::Off,
                other => anyhow::bail!(
                    "invalid value `{other}` for check `{id}` in moat.toml — expected `on` or `off`"
                ),
            };
            checks.insert(id, state);
        }
        Ok(Self {
            checks,
            release_branches: raw.release_branches,
        })
    }

    pub fn is_off(&self, check_id: &str) -> bool {
        matches!(self.checks.get(check_id), Some(CheckState::Off))
    }

    pub fn release_branches(&self) -> &[String] {
        &self.release_branches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_off_and_on() {
        let cfg = Config::parse(
            r#"
                [checks]
                signed_commits = "off"
                pinned_actions = "on"
            "#,
        )
        .unwrap();
        assert!(cfg.is_off("signed_commits"));
        assert!(!cfg.is_off("pinned_actions"));
    }

    #[test]
    fn empty_config_is_valid() {
        let cfg = Config::parse("").unwrap();
        assert!(!cfg.is_off("anything"));
    }

    #[test]
    fn rejects_unknown_values() {
        let err = Config::parse(
            r#"
                [checks]
                signed_commits = "warning"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid value"));
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(Config::parse("not = valid = toml").is_err());
    }
}
