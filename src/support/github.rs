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

pub struct Client {
    http: reqwest::Client,
    base_url: String,
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

impl Client {
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
