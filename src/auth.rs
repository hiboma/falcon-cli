use crate::config::Config;
use crate::error::{FalconError, Result};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: u64,
}

#[derive(Debug, Clone)]
pub struct Auth {
    config: Config,
    token: Arc<RwLock<Option<String>>>,
    http: reqwest::Client,
}

impl Auth {
    pub fn new(config: Config) -> Self {
        let http = reqwest::Client::new();
        Self {
            config,
            token: Arc::new(RwLock::new(None)),
            http,
        }
    }

    /// Get a valid access token, requesting a new one if needed.
    pub async fn get_token(&self) -> Result<String> {
        {
            let guard = self.token.read().await;
            if let Some(ref t) = *guard {
                return Ok(t.clone());
            }
        }
        self.refresh_token().await
    }

    /// Force-refresh the OAuth2 token using client credentials.
    pub async fn refresh_token(&self) -> Result<String> {
        let mut guard = self.token.write().await;

        // Double-check after acquiring write lock to avoid redundant refreshes.
        if let Some(ref t) = *guard {
            return Ok(t.clone());
        }

        let url = format!("{}/oauth2/token", self.config.base_url);
        let mut params = vec![
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];
        if let Some(ref cid) = self.config.member_cid {
            params.push(("member_cid", cid.as_str()));
        }

        let resp = self.http.post(&url).form(&params).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let mut body = resp.text().await.unwrap_or_default();
            body.truncate(200);
            return Err(FalconError::Auth(format!("{}: {}", status, body)));
        }

        let token_resp: TokenResponse = resp.json().await?;
        *guard = Some(token_resp.access_token.clone());
        Ok(token_resp.access_token)
    }

    /// Invalidate the cached token so the next request triggers a refresh.
    pub async fn invalidate(&self) {
        let mut guard = self.token.write().await;
        *guard = None;
    }
}
