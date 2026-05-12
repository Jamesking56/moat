use crate::support::panel;
use serde::Deserialize;

pub(crate) async fn traced<F, T>(prefix: Option<&str>, label: &str, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let out = fut.await;
    match prefix {
        Some(p) => panel::progress(&format!("{p}: {label}")),
        None => panel::progress(label),
    }
    out
}

#[derive(Clone, Copy)]
pub enum WorkflowTokenState {
    Read,
    Write,
    Unavailable,
}

#[derive(Deserialize)]
pub(crate) struct CollaboratorEntry {
    pub login: String,
    #[serde(default)]
    pub permissions: CollaboratorPerms,
}

#[derive(Deserialize, Default)]
pub(crate) struct CollaboratorPerms {
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub maintain: bool,
    #[serde(default)]
    pub push: bool,
    #[serde(default)]
    pub triage: bool,
}

impl CollaboratorPerms {
    pub fn is_more_than_read(&self) -> bool {
        self.admin || self.maintain || self.push || self.triage
    }
}
