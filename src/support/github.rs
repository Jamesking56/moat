use anyhow::{Context, Result, anyhow};
use reqwest::{StatusCode, header};
use serde::de::DeserializeOwned;
use std::process::Command;

const USER_AGENT: &str = concat!("moat/", env!("CARGO_PKG_VERSION"));
pub const DEFAULT_API: &str = "https://api.github.com";
const API_BASE_ENV: &str = "MOAT_GITHUB_API_BASE";

pub fn resolve_token() -> Result<String> {
    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(v) = std::env::var(var)
            && !v.trim().is_empty()
        {
            return Ok(v);
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
    Ok(token)
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

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<T>> {
        let url = self.url(path);
        let resp = self.http.get(&url).send().await?;
        match resp.status() {
            StatusCode::OK => Ok(Fetch::Ok(resp.json().await?)),
            StatusCode::NO_CONTENT => Err(anyhow!("expected JSON body, got 204 from {url}")),
            StatusCode::NOT_FOUND => Ok(Fetch::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => Ok(Fetch::Forbidden),
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
        match resp.status() {
            StatusCode::OK => Ok(Fetch403::Ok(resp.json().await?)),
            StatusCode::NO_CONTENT => Err(anyhow!("expected JSON body, got 204 from {url}")),
            StatusCode::NOT_FOUND => Ok(Fetch403::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("Upgrade to GitHub") {
                    Ok(Fetch403::PlanGated)
                } else {
                    Ok(Fetch403::Forbidden)
                }
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
        match resp.status() {
            StatusCode::OK => Ok(Fetch::Ok(resp.text().await?)),
            StatusCode::NOT_FOUND => Ok(Fetch::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => Ok(Fetch::Forbidden),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(anyhow!("GET {url} -> {s}: {body}"))
            }
        }
    }

    pub async fn get_presence(&self, path: &str) -> Result<Fetch<()>> {
        let url = self.url(path);
        let resp = self.http.get(&url).send().await?;
        match resp.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(Fetch::Ok(())),
            StatusCode::NOT_FOUND => Ok(Fetch::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => Ok(Fetch::Forbidden),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(anyhow!("GET {url} -> {s}: {body}"))
            }
        }
    }

    pub async fn get_presence_plan_aware(&self, path: &str) -> Result<Fetch403<()>> {
        let url = self.url(path);
        let resp = self.http.get(&url).send().await?;
        match resp.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(Fetch403::Ok(())),
            StatusCode::NOT_FOUND => Ok(Fetch403::NotFound),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY => {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("Upgrade to GitHub") {
                    Ok(Fetch403::PlanGated)
                } else {
                    Ok(Fetch403::Forbidden)
                }
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
                            return Ok(Fetch::Forbidden);
                        }
                        StatusCode::NOT_FOUND => return Ok(Fetch::NotFound),
                        _ => {}
                    }
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
                            let body = resp.text().await.unwrap_or_default();
                            if body.contains("Upgrade to GitHub") {
                                return Ok(Fetch403::PlanGated);
                            }
                            return Ok(Fetch403::Forbidden);
                        }
                        StatusCode::NOT_FOUND => return Ok(Fetch403::NotFound),
                        _ => {}
                    }
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
}
