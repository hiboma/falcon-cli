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
    pub fn new(auth: Auth, base_url: String) -> Self {
        let http = reqwest::Client::new();
        Self {
            auth,
            http,
            base_url,
        }
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
}
