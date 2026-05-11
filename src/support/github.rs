use anyhow::{Context, Result, anyhow};
use reqwest::{StatusCode, header};
use serde::de::DeserializeOwned;
use std::process::Command;

const USER_AGENT: &str = concat!("moat/", env!("CARGO_PKG_VERSION"));
const API: &str = "https://api.github.com";

pub fn resolve_token() -> Result<String> {
    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                return Ok(v);
            }
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
        return Err(anyhow!("`gh auth token` returned empty output; run `gh auth login` first"));
    }
    Ok(token)
}

pub struct Client {
    http: reqwest::Client,
}

pub enum Fetch<T> {
    Ok(T),
    NotFound,
    Forbidden,
}

impl Client {
    pub fn new(token: String) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        let mut auth = header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        auth.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth);
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("application/vnd.github+json"));
        headers.insert("X-GitHub-Api-Version", header::HeaderValue::from_static("2022-11-28"));

        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(headers)
            .build()?;

        Ok(Self { http })
    }

    fn url(path: &str) -> String {
        if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{API}{path}")
        }
    }

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<Fetch<T>> {
        let url = Self::url(path);
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

    pub async fn get_presence(&self, path: &str) -> Result<Fetch<()>> {
        let url = Self::url(path);
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
        let mut next = Some(format!("{}{sep}per_page=100", Self::url(path)));
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
