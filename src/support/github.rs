use anyhow::{Context, Result, anyhow};
use reqwest::{StatusCode, header};
use serde::de::DeserializeOwned;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const USER_AGENT: &str = concat!("moat/", env!("CARGO_PKG_VERSION"));
pub const DEFAULT_API: &str = "https://api.github.com";
const API_BASE_ENV: &str = "MOAT_GITHUB_API_BASE";

/// Where the GitHub token came from. Drives the remediation copy moat shows
/// when the token turns out to be under-scoped, SAML-blocked, or rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthSource {
    /// `GITHUB_TOKEN` environment variable.
    GithubTokenEnv,
    /// `GH_TOKEN` environment variable.
    GhTokenEnv,
    /// Output of `gh auth token`.
    GhCli,
}

impl std::fmt::Display for AuthSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthSource::GithubTokenEnv => "GITHUB_TOKEN",
            AuthSource::GhTokenEnv => "GH_TOKEN",
            AuthSource::GhCli => "gh auth token",
        };
        f.write_str(s)
    }
}

pub fn resolve_token() -> Result<(String, AuthSource)> {
    for (var, src) in [
        ("GITHUB_TOKEN", AuthSource::GithubTokenEnv),
        ("GH_TOKEN", AuthSource::GhTokenEnv),
    ] {
        if let Ok(v) = std::env::var(var)
            && !v.trim().is_empty()
        {
            return Ok((v, src));
        }
    }

    let out = Command::new("gh")
        .args(["auth", "token"])
        .output()
        .context("no GITHUB_TOKEN/GH_TOKEN set and could not run `gh auth token` (is the gh CLI installed?)")?;

    if !out.status.success() {
        return Err(anyhow!(
            "`gh auth token` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let token = String::from_utf8(out.stdout)?.trim().to_string();
    if token.is_empty() {
        return Err(anyhow!(
            "`gh auth token` returned empty output; run `gh auth login` first"
        ));
    }
    Ok((token, AuthSource::GhCli))
}

/// Result of probing `GET /user` at startup. See [`HttpGitHubClient::preflight`].
#[derive(Debug, Clone)]
pub struct Preflight {
    /// Granted OAuth scopes for classic PATs / gh OAuth tokens. `None` when the
    /// token type doesn't expose scopes (fine-grained PATs, GitHub App tokens).
    pub scopes: Option<Vec<String>>,
    /// If the org under audit requires SAML SSO and the token isn't authorized
    /// for it, this carries the authorization URL GitHub returned.
    pub sso_url: Option<String>,
    /// True when GitHub returned 401 Unauthorized for `GET /user`. The runner
    /// formats a source-aware error so the user knows which token was rejected.
    pub rejected: bool,
}

/// If the response looks like a GitHub rate-limit (primary or secondary),
/// return a formatted multi-line error explaining when to retry. Returns
/// `None` for normal permission failures so callers fall through to their
/// existing 403 handling.
fn rate_limit_error(
    status: StatusCode,
    headers: &header::HeaderMap,
    body: &str,
) -> Option<anyhow::Error> {
    let remaining_zero = headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        == Some(0);
    let body_lc = body.to_ascii_lowercase();
    let body_mentions_rate_limit = body_lc.contains("rate limit")
        || body_lc.contains("secondary rate limit")
        || body_lc.contains("abuse detection");

    let is_429 = status == StatusCode::TOO_MANY_REQUESTS;
    let is_403_rate_limited = status == StatusCode::FORBIDDEN
        && (remaining_zero || body_mentions_rate_limit);

    if !is_429 && !is_403_rate_limited {
        return None;
    }

    let kind = if remaining_zero {
        "primary"
    } else {
        "secondary"
    };

    let retry_in_secs = retry_after_seconds(headers);
    let when = retry_in_secs
        .map(format_retry_hint)
        .unwrap_or_else(|| "in a few minutes".to_string());

    let mut msg = format!(
        "GitHub API rate limit reached ({kind}). Try again {when}."
    );
    if kind == "primary" {
        msg.push_str(
            "\n\nAuthenticated requests get 5,000/hour. To raise this, run moat \
             against fewer repos at once, or use a token tied to a GitHub App \
             installation (15,000/hour).",
        );
    } else {
        msg.push_str(
            "\n\nGitHub throttles bursts of concurrent requests. Wait for the \
             window above to pass and re-run moat.",
        );
    }
    Some(anyhow!(msg))
}

/// Seconds until the user can retry, derived from `Retry-After` (secondary
/// rate limits) or `X-RateLimit-Reset` (primary rate limits, unix epoch).
fn retry_after_seconds(headers: &header::HeaderMap) -> Option<i64> {
    if let Some(v) = headers.get("retry-after").and_then(|v| v.to_str().ok())
        && let Ok(secs) = v.trim().parse::<i64>()
    {
        return Some(secs.max(0));
    }
    if let Some(reset) = headers
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
    {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        return Some((reset - now).max(0));
    }
    None
}

fn format_retry_hint(secs: i64) -> String {
    if secs <= 0 {
        return "now (please retry)".to_string();
    }
    if secs < 60 {
        return format!("in {secs} second{}", if secs == 1 { "" } else { "s" });
    }
    let mins = (secs + 59) / 60;
    if mins < 60 {
        return format!("in {mins} minute{}", if mins == 1 { "" } else { "s" });
    }
    let hours = mins / 60;
    let rem = mins % 60;
    if rem == 0 {
        format!("in {hours} hour{}", if hours == 1 { "" } else { "s" })
    } else {
        format!(
            "in {hours} hour{} {rem} minute{}",
            if hours == 1 { "" } else { "s" },
            if rem == 1 { "" } else { "s" }
        )
    }
}

fn sso_url_from(headers: &header::HeaderMap) -> Option<String> {
    let raw = headers.get("x-github-sso")?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("url=") {
            return Some(rest.to_string());
        }
    }
    None
}

#[derive(Debug)]
pub enum Fetch<T> {
    Ok(T),
    NotFound,
    Forbidden,
}

#[derive(Debug)]
pub enum Fetch403<T> {
    Ok(T),
    NotFound,
    Forbidden,
    PlanGated,
}

#[allow(async_fn_in_trait)]
pub trait GitHubClient {
    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<T>>;
    async fn get_json_plan_aware<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch403<T>>;
    async fn get_raw(&self, path: &str) -> Result<Fetch<String>>;
    async fn get_presence(&self, path: &str) -> Result<Fetch<()>>;
    async fn get_presence_plan_aware(&self, path: &str) -> Result<Fetch403<()>>;
    async fn get_paginated<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<Vec<T>>>;
    async fn get_paginated_plan_aware<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Fetch403<Vec<T>>>;
    async fn preflight(&self) -> Result<Preflight>;
}

pub type Client = HttpGitHubClient;

pub struct HttpGitHubClient {
    http: reqwest::Client,
    base_url: String,
}

impl HttpGitHubClient {
    pub fn new(token: String) -> Result<Self> {
        let base = std::env::var(API_BASE_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_API.to_string());
        Self::with_base_url(token, base)
    }

    pub fn with_base_url(token: String, base_url: impl Into<String>) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        let mut auth = header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        auth.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth);
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "X-GitHub-Api-Version",
            header::HeaderValue::from_static("2022-11-28"),
        );

        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(headers)
            .build()?;

        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{}", self.base_url, path)
        }
    }

    /// Probe `GET /user` to discover what kind of token we have and (for OAuth
    /// tokens) which scopes it carries. Used by the runner to fail fast with a
    /// clear message before any check fires a 403 mid-run.
    ///
    /// Behaviour:
    /// - 200 with `X-OAuth-Scopes` header → classic PAT / gh OAuth token; the
    ///   scopes list is returned so the caller can diff against requirements.
    /// - 200 without the scope header → fine-grained PAT or GitHub App token;
    ///   scopes is `None` and the caller should skip scope validation (these
    ///   use granular permissions instead).
    /// - 401 → token rejected outright; surface a clear auth error.
    /// - 403 with SAML SSO hint → token isn't authorized for the org; surface
    ///   the authorization URL GitHub returns.
    pub async fn preflight(&self) -> Result<Preflight> {
        let url = self.url("/user");
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        let sso_url = sso_url_from(resp.headers());
        let scopes_header = resp
            .headers()
            .get("x-oauth-scopes")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        match status {
            StatusCode::OK => {
                let scopes = scopes_header.map(|s| {
                    s.split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect::<Vec<_>>()
                });
                Ok(Preflight {
                    scopes,
                    sso_url: None,
                    rejected: false,
                })
            }
            StatusCode::UNAUTHORIZED => Ok(Preflight {
                scopes: None,
                sso_url: None,
                rejected: true,
            }),
            StatusCode::FORBIDDEN if sso_url.is_some() => Ok(Preflight {
                scopes: None,
                sso_url,
                rejected: false,
            }),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(anyhow!("GET {url} -> {s}: {body}"))
            }
        }
    }

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<T>> {
        let url = self.url(path);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        match status {
            StatusCode::OK => Ok(Fetch::Ok(resp.json().await?)),
            StatusCode::NO_CONTENT => Err(anyhow!("expected JSON body, got 204 from {url}")),
            StatusCode::NOT_FOUND => Ok(Fetch::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                if let Some(err) = rate_limit_error(status, &headers, &body) {
                    return Err(err);
                }
                Ok(Fetch::Forbidden)
            }
            StatusCode::TOO_MANY_REQUESTS => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                Err(rate_limit_error(status, &headers, &body)
                    .unwrap_or_else(|| anyhow!("GET {url} -> {status}: {body}")))
            }
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(anyhow!("GET {url} -> {s}: {body}"))
            }
        }
    }

    pub async fn get_json_plan_aware<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Fetch403<T>> {
        let url = self.url(path);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        match status {
            StatusCode::OK => Ok(Fetch403::Ok(resp.json().await?)),
            StatusCode::NO_CONTENT => Err(anyhow!("expected JSON body, got 204 from {url}")),
            StatusCode::NOT_FOUND => Ok(Fetch403::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                if let Some(err) = rate_limit_error(status, &headers, &body) {
                    return Err(err);
                }
                if body.contains("Upgrade to GitHub") {
                    Ok(Fetch403::PlanGated)
                } else {
                    Ok(Fetch403::Forbidden)
                }
            }
            StatusCode::TOO_MANY_REQUESTS => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                Err(rate_limit_error(status, &headers, &body)
                    .unwrap_or_else(|| anyhow!("GET {url} -> {status}: {body}")))
            }
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(anyhow!("GET {url} -> {s}: {body}"))
            }
        }
    }

    pub async fn get_raw(&self, path: &str) -> Result<Fetch<String>> {
        let url = self.url(path);
        let resp = self
            .http
            .get(&url)
            .header(header::ACCEPT, "application/vnd.github.raw")
            .send()
            .await?;
        let status = resp.status();
        match status {
            StatusCode::OK => Ok(Fetch::Ok(resp.text().await?)),
            StatusCode::NOT_FOUND => Ok(Fetch::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                if let Some(err) = rate_limit_error(status, &headers, &body) {
                    return Err(err);
                }
                Ok(Fetch::Forbidden)
            }
            StatusCode::TOO_MANY_REQUESTS => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                Err(rate_limit_error(status, &headers, &body)
                    .unwrap_or_else(|| anyhow!("GET {url} -> {status}: {body}")))
            }
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(anyhow!("GET {url} -> {s}: {body}"))
            }
        }
    }

    pub async fn get_presence(&self, path: &str) -> Result<Fetch<()>> {
        let url = self.url(path);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        match status {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(Fetch::Ok(())),
            StatusCode::NOT_FOUND => Ok(Fetch::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                if let Some(err) = rate_limit_error(status, &headers, &body) {
                    return Err(err);
                }
                Ok(Fetch::Forbidden)
            }
            StatusCode::TOO_MANY_REQUESTS => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                Err(rate_limit_error(status, &headers, &body)
                    .unwrap_or_else(|| anyhow!("GET {url} -> {status}: {body}")))
            }
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(anyhow!("GET {url} -> {s}: {body}"))
            }
        }
    }

    pub async fn get_presence_plan_aware(&self, path: &str) -> Result<Fetch403<()>> {
        let url = self.url(path);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        match status {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(Fetch403::Ok(())),
            StatusCode::NOT_FOUND => Ok(Fetch403::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                if let Some(err) = rate_limit_error(status, &headers, &body) {
                    return Err(err);
                }
                if body.contains("Upgrade to GitHub") {
                    Ok(Fetch403::PlanGated)
                } else {
                    Ok(Fetch403::Forbidden)
                }
            }
            StatusCode::TOO_MANY_REQUESTS => {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                Err(rate_limit_error(status, &headers, &body)
                    .unwrap_or_else(|| anyhow!("GET {url} -> {status}: {body}")))
            }
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(anyhow!("GET {url} -> {s}: {body}"))
            }
        }
    }

    pub async fn get_paginated<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<Vec<T>>> {
        let mut out = Vec::new();
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut next = Some(format!("{}{sep}per_page=100", self.url(path)));
        let mut first = true;

        while let Some(url) = next {
            let resp = self.http.get(&url).send().await?;
            let status = resp.status();
            if !status.is_success() {
                if first {
                    match status {
                        StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => {
                            let headers = resp.headers().clone();
                            let body = resp.text().await.unwrap_or_default();
                            if let Some(err) = rate_limit_error(status, &headers, &body) {
                                return Err(err);
                            }
                            return Ok(Fetch::Forbidden);
                        }
                        StatusCode::NOT_FOUND => return Ok(Fetch::NotFound),
                        StatusCode::TOO_MANY_REQUESTS => {
                            let headers = resp.headers().clone();
                            let body = resp.text().await.unwrap_or_default();
                            return Err(rate_limit_error(status, &headers, &body)
                                .unwrap_or_else(|| anyhow!("GET {url} -> {status}: {body}")));
                        }
                        _ => {}
                    }
                } else if status == StatusCode::TOO_MANY_REQUESTS
                    || status == StatusCode::FORBIDDEN
                {
                    let headers = resp.headers().clone();
                    let body = resp.text().await.unwrap_or_default();
                    if let Some(err) = rate_limit_error(status, &headers, &body) {
                        return Err(err);
                    }
                    return Err(anyhow!("GET {url} -> {status}: {body}"));
                }
                let body = resp.text().await.unwrap_or_default();
                return Err(anyhow!("GET {url} -> {status}: {body}"));
            }
            next = next_link(resp.headers());
            let page: Vec<T> = resp.json().await?;
            out.extend(page);
            first = false;
        }

        Ok(Fetch::Ok(out))
    }

    pub async fn get_paginated_plan_aware<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Fetch403<Vec<T>>> {
        let mut out = Vec::new();
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut next = Some(format!("{}{sep}per_page=100", self.url(path)));
        let mut first = true;

        while let Some(url) = next {
            let resp = self.http.get(&url).send().await?;
            let status = resp.status();
            if !status.is_success() {
                if first {
                    match status {
                        StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => {
                            let headers = resp.headers().clone();
                            let body = resp.text().await.unwrap_or_default();
                            if let Some(err) = rate_limit_error(status, &headers, &body) {
                                return Err(err);
                            }
                            if body.contains("Upgrade to GitHub") {
                                return Ok(Fetch403::PlanGated);
                            }
                            return Ok(Fetch403::Forbidden);
                        }
                        StatusCode::NOT_FOUND => return Ok(Fetch403::NotFound),
                        StatusCode::TOO_MANY_REQUESTS => {
                            let headers = resp.headers().clone();
                            let body = resp.text().await.unwrap_or_default();
                            return Err(rate_limit_error(status, &headers, &body)
                                .unwrap_or_else(|| anyhow!("GET {url} -> {status}: {body}")));
                        }
                        _ => {}
                    }
                } else if status == StatusCode::TOO_MANY_REQUESTS
                    || status == StatusCode::FORBIDDEN
                {
                    let headers = resp.headers().clone();
                    let body = resp.text().await.unwrap_or_default();
                    if let Some(err) = rate_limit_error(status, &headers, &body) {
                        return Err(err);
                    }
                    return Err(anyhow!("GET {url} -> {status}: {body}"));
                }
                let body = resp.text().await.unwrap_or_default();
                return Err(anyhow!("GET {url} -> {status}: {body}"));
            }
            next = next_link(resp.headers());
            let page: Vec<T> = resp.json().await?;
            out.extend(page);
            first = false;
        }

        Ok(Fetch403::Ok(out))
    }
}

impl GitHubClient for HttpGitHubClient {
    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<T>> {
        HttpGitHubClient::get_json(self, path).await
    }
    async fn get_json_plan_aware<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch403<T>> {
        HttpGitHubClient::get_json_plan_aware(self, path).await
    }
    async fn get_raw(&self, path: &str) -> Result<Fetch<String>> {
        HttpGitHubClient::get_raw(self, path).await
    }
    async fn get_presence(&self, path: &str) -> Result<Fetch<()>> {
        HttpGitHubClient::get_presence(self, path).await
    }
    async fn get_presence_plan_aware(&self, path: &str) -> Result<Fetch403<()>> {
        HttpGitHubClient::get_presence_plan_aware(self, path).await
    }
    async fn get_paginated<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<Vec<T>>> {
        HttpGitHubClient::get_paginated(self, path).await
    }
    async fn get_paginated_plan_aware<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Fetch403<Vec<T>>> {
        HttpGitHubClient::get_paginated_plan_aware(self, path).await
    }
    async fn preflight(&self) -> Result<Preflight> {
        HttpGitHubClient::preflight(self).await
    }
}

fn next_link(headers: &header::HeaderMap) -> Option<String> {
    let link = headers.get(header::LINK)?.to_str().ok()?;
    for part in link.split(',') {
        let part = part.trim();
        if part.ends_with(r#"rel="next""#) {
            let start = part.find('<')? + 1;
            let end = part.find('>')?;
            return Some(part[start..end].to_string());
        }
    }
    None
}

#[doc(hidden)]
#[derive(Clone)]
pub enum FakeResponse {
    Json(serde_json::Value),
    Raw(String),
    Empty,
    NotFound,
    Forbidden,
    PlanGated,
}

#[doc(hidden)]
#[derive(Default)]
pub struct FakeGitHubClient {
    responses: std::sync::Mutex<std::collections::HashMap<String, FakeResponse>>,
    paginated: std::sync::Mutex<std::collections::HashMap<String, Vec<serde_json::Value>>>,
}

#[doc(hidden)]
impl FakeGitHubClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_json(self, path: impl Into<String>, body: serde_json::Value) -> Self {
        self.insert(path, FakeResponse::Json(body));
        self
    }

    pub fn with_raw(self, path: impl Into<String>, body: impl Into<String>) -> Self {
        self.insert(path, FakeResponse::Raw(body.into()));
        self
    }

    pub fn with_status(self, path: impl Into<String>, status: u16) -> Self {
        let resp = match status {
            200 | 204 => FakeResponse::Empty,
            404 => FakeResponse::NotFound,
            403 | 422 => FakeResponse::Forbidden,
            other => panic!("FakeGitHubClient: unsupported status {other}"),
        };
        self.insert(path, resp);
        self
    }

    pub fn with_not_found(self, path: impl Into<String>) -> Self {
        self.insert(path, FakeResponse::NotFound);
        self
    }

    pub fn with_forbidden(self, path: impl Into<String>) -> Self {
        self.insert(path, FakeResponse::Forbidden);
        self
    }

    pub fn with_plan_gated(self, path: impl Into<String>) -> Self {
        self.insert(path, FakeResponse::PlanGated);
        self
    }

    pub fn with_paginated(self, path: impl Into<String>, items: Vec<serde_json::Value>) -> Self {
        self.paginated.lock().unwrap().insert(path.into(), items);
        self
    }

    fn insert(&self, path: impl Into<String>, resp: FakeResponse) {
        self.responses.lock().unwrap().insert(path.into(), resp);
    }

    fn lookup(&self, path: &str) -> Option<FakeResponse> {
        let map = self.responses.lock().unwrap();
        if let Some(v) = map.get(path) {
            return Some(v.clone());
        }
        map.get(strip_query(path)).cloned()
    }

    fn lookup_paginated(&self, path: &str) -> Option<Vec<serde_json::Value>> {
        let map = self.paginated.lock().unwrap();
        if let Some(v) = map.get(path) {
            return Some(v.clone());
        }
        map.get(strip_query(path)).cloned()
    }
}

fn strip_query(path: &str) -> &str {
    match path.find('?') {
        Some(i) => &path[..i],
        None => path,
    }
}

impl GitHubClient for FakeGitHubClient {
    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<T>> {
        Ok(match self.lookup(path) {
            Some(FakeResponse::Json(v)) => Fetch::Ok(serde_json::from_value(v)?),
            Some(FakeResponse::Raw(s)) => Fetch::Ok(serde_json::from_str(&s)?),
            Some(FakeResponse::Empty) => {
                return Err(anyhow!("FakeGitHubClient: empty body for JSON path {path}"));
            }
            Some(FakeResponse::Forbidden) | Some(FakeResponse::PlanGated) => Fetch::Forbidden,
            Some(FakeResponse::NotFound) | None => Fetch::NotFound,
        })
    }

    async fn get_json_plan_aware<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch403<T>> {
        Ok(match self.lookup(path) {
            Some(FakeResponse::Json(v)) => Fetch403::Ok(serde_json::from_value(v)?),
            Some(FakeResponse::Raw(s)) => Fetch403::Ok(serde_json::from_str(&s)?),
            Some(FakeResponse::Empty) => {
                return Err(anyhow!("FakeGitHubClient: empty body for JSON path {path}"));
            }
            Some(FakeResponse::PlanGated) => Fetch403::PlanGated,
            Some(FakeResponse::Forbidden) => Fetch403::Forbidden,
            Some(FakeResponse::NotFound) | None => Fetch403::NotFound,
        })
    }

    async fn get_raw(&self, path: &str) -> Result<Fetch<String>> {
        Ok(match self.lookup(path) {
            Some(FakeResponse::Raw(s)) => Fetch::Ok(s),
            Some(FakeResponse::Json(v)) => Fetch::Ok(serde_json::to_string(&v)?),
            Some(FakeResponse::Empty) => Fetch::Ok(String::new()),
            Some(FakeResponse::Forbidden) | Some(FakeResponse::PlanGated) => Fetch::Forbidden,
            Some(FakeResponse::NotFound) | None => Fetch::NotFound,
        })
    }

    async fn get_presence(&self, path: &str) -> Result<Fetch<()>> {
        Ok(match self.lookup(path) {
            Some(FakeResponse::Json(_))
            | Some(FakeResponse::Raw(_))
            | Some(FakeResponse::Empty) => Fetch::Ok(()),
            Some(FakeResponse::Forbidden) | Some(FakeResponse::PlanGated) => Fetch::Forbidden,
            Some(FakeResponse::NotFound) | None => Fetch::NotFound,
        })
    }

    async fn get_presence_plan_aware(&self, path: &str) -> Result<Fetch403<()>> {
        Ok(match self.lookup(path) {
            Some(FakeResponse::Json(_))
            | Some(FakeResponse::Raw(_))
            | Some(FakeResponse::Empty) => Fetch403::Ok(()),
            Some(FakeResponse::PlanGated) => Fetch403::PlanGated,
            Some(FakeResponse::Forbidden) => Fetch403::Forbidden,
            Some(FakeResponse::NotFound) | None => Fetch403::NotFound,
        })
    }

    async fn get_paginated<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<Vec<T>>> {
        if let Some(resp) = self.lookup(path) {
            match resp {
                FakeResponse::Forbidden | FakeResponse::PlanGated => return Ok(Fetch::Forbidden),
                FakeResponse::NotFound => return Ok(Fetch::NotFound),
                _ => {}
            }
        }
        let Some(items) = self.lookup_paginated(path) else {
            return Ok(Fetch::NotFound);
        };
        let mut out = Vec::with_capacity(items.len());
        for v in items {
            out.push(serde_json::from_value(v)?);
        }
        Ok(Fetch::Ok(out))
    }

    async fn get_paginated_plan_aware<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Fetch403<Vec<T>>> {
        if let Some(resp) = self.lookup(path) {
            match resp {
                FakeResponse::PlanGated => return Ok(Fetch403::PlanGated),
                FakeResponse::Forbidden => return Ok(Fetch403::Forbidden),
                FakeResponse::NotFound => return Ok(Fetch403::NotFound),
                _ => {}
            }
        }
        let Some(items) = self.lookup_paginated(path) else {
            return Ok(Fetch403::NotFound);
        };
        let mut out = Vec::with_capacity(items.len());
        for v in items {
            out.push(serde_json::from_value(v)?);
        }
        Ok(Fetch403::Ok(out))
    }

    async fn preflight(&self) -> Result<Preflight> {
        // Tests don't exercise the scope gate; default to a fine-grained-style
        // token (no scopes header) so the runner skips validation.
        Ok(Preflight {
            scopes: None,
            sso_url: None,
            rejected: false,
        })
    }
}
