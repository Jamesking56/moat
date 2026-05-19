use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);

fn cache_file() -> Option<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(PathBuf::from(home).join(".moat").join("latest-version"))
}

fn is_cache_fresh() -> bool {
    let Some(path) = cache_file() else {
        return false;
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|d| d < CHECK_INTERVAL)
        .unwrap_or(false)
}

fn read_cache() -> Option<String> {
    let path = cache_file()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let v = raw.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

fn write_cache(version: &str) {
    let Some(path) = cache_file() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, version.as_bytes());
}

fn fetch_latest_from_github() -> Option<String> {
    let mut builder = self_update::backends::github::Update::configure();
    builder
        .repo_owner("laravel")
        .repo_name("moat")
        .bin_name("moat")
        .current_version(env!("CARGO_PKG_VERSION"));
    if let Ok((token, _)) = crate::support::github::resolve_token() {
        builder.auth_token(&token);
    }
    let updater = builder.build().ok()?;
    let release = updater.get_latest_release().ok()?;
    Some(release.version)
}

/// Best-effort lookup of the latest released version. Uses a daily on-disk
/// cache so repeated runs don't hit the network. Returns `None` when offline,
/// rate-limited, or otherwise unable to reach GitHub.
pub fn latest_version() -> Option<String> {
    if is_cache_fresh() {
        return read_cache();
    }
    let latest = fetch_latest_from_github()?;
    write_cache(&latest);
    Some(latest)
}

pub fn is_newer_than_current(latest: &str) -> bool {
    parse_version(latest) > parse_version(env!("CARGO_PKG_VERSION"))
}

fn parse_version(s: &str) -> (u32, u32, u32) {
    let s = s.trim().trim_start_matches('v');
    let mut parts = s.split('.').map(|x| x.parse::<u32>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

/// Perform an explicit self-update. Returns `Some(version)` if the on-disk
/// binary was actually replaced, `None` otherwise. Only invoked when the user
/// passes `--self-update`.
pub fn run_self_update() -> Option<String> {
    let current = env!("CARGO_PKG_VERSION");

    let mut builder = self_update::backends::github::Update::configure();
    builder
        .repo_owner("laravel")
        .repo_name("moat")
        .bin_name("moat")
        .bin_path_in_archive("moat-{{ version }}-{{ target }}/{{ bin }}")
        .show_output(false)
        .show_download_progress(false)
        .no_confirm(true)
        .current_version(current);

    if let Ok((token, _)) = crate::support::github::resolve_token() {
        builder.auth_token(&token);
    }

    let updater = builder.build().ok()?;
    let status = updater.update().ok()?;
    write_cache(status.version());
    if status.updated() {
        Some(status.version().to_string())
    } else {
        None
    }
}
