use crate::auth::Auth;
use crate::error::{FalconError, Result};
use reqwest::StatusCode;

#[derive(Debug, Clone)]
pub struct FalconClient {
    auth: Auth,
    http: reqwest::Client,
    base_url: String,
}

impl FalconClient {
    pub fn new(auth: Auth, base_url: String) -> Result<Self> {
        if !base_url.starts_with("https://")
            && !base_url.starts_with("http://localhost")
            && !base_url.starts_with("http://127.0.0.1")
        {
            return Err(FalconError::Config(format!(
                "base_url must use HTTPS (got: {}). HTTP is only allowed for localhost and 127.0.0.1.",
                base_url
            )));
        }

        let http = reqwest::Client::new();
        Ok(Self {
            auth,
            http,
            base_url,
        })
    }

    /// Send a GET request with automatic re-authentication on 401.
    pub async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.get_token().await?;
        let resp = self.http.get(&url).bearer_auth(&token).send().await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            self.auth.invalidate().await;
            let new_token = self.auth.refresh_token().await?;
            let retry_resp = self.http.get(&url).bearer_auth(&new_token).send().await?;
            return Self::handle_response(retry_resp).await;
        }

        Self::handle_response(resp).await
    }

    /// Send a POST request with JSON body and automatic re-authentication on 401.
    pub async fn post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.get_token().await?;
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            self.auth.invalidate().await;
            let new_token = self.auth.refresh_token().await?;
            let retry_resp = self
                .http
                .post(&url)
                .bearer_auth(&new_token)
                .json(body)
                .send()
                .await?;
            return Self::handle_response(retry_resp).await;
        }

        Self::handle_response(resp).await
    }

    /// Send a PATCH request with JSON body and automatic re-authentication on 401.
    #[allow(dead_code)]
    pub async fn patch(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.get_token().await?;
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            self.auth.invalidate().await;
            let new_token = self.auth.refresh_token().await?;
            let retry_resp = self
                .http
                .patch(&url)
                .bearer_auth(&new_token)
                .json(body)
                .send()
                .await?;
            return Self::handle_response(retry_resp).await;
        }

        Self::handle_response(resp).await
    }

    /// Send a GET request and return raw bytes with automatic re-authentication on 401.
    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.get_token().await?;
        let resp = self.http.get(&url).bearer_auth(&token).send().await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            self.auth.invalidate().await;
            let new_token = self.auth.refresh_token().await?;
            let retry_resp = self.http.get(&url).bearer_auth(&new_token).send().await?;
            return Self::handle_bytes_response(retry_resp).await;
        }

        Self::handle_bytes_response(resp).await
    }

    /// Send a DELETE request with automatic re-authentication on 401.
    #[allow(dead_code)]
    pub async fn delete(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.get_token().await?;
        let resp = self.http.delete(&url).bearer_auth(&token).send().await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            self.auth.invalidate().await;
            let new_token = self.auth.refresh_token().await?;
            let retry_resp = self
                .http
                .delete(&url)
                .bearer_auth(&new_token)
                .send()
                .await?;
            return Self::handle_response(retry_resp).await;
        }

        Self::handle_response(resp).await
    }

    async fn handle_response(resp: reqwest::Response) -> Result<serde_json::Value> {
        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            let mut truncated = body.clone();
            truncated.truncate(200);
            return Err(FalconError::Api(format!("{}: {}", status, truncated)));
        }

        let value: serde_json::Value = serde_json::from_str(&body)?;
        Ok(value)
    }

    async fn handle_bytes_response(resp: reqwest::Response) -> Result<Vec<u8>> {
        let status = resp.status();

        if !status.is_success() {
            let body = resp.text().await?;
            let mut truncated = body;
            truncated.truncate(200);
            return Err(FalconError::Api(format!("{}: {}", status, truncated)));
        }

        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }
}
