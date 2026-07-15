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
        if !base_url.starts_with("https://") && !Self::is_loopback_http(&base_url) {
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
            return Err(FalconError::Api(format!(
                "{}: {}",
                status,
                Self::truncate_chars(&body, 200)
            )));
        }

        // 204 No Content and other empty success bodies are not JSON.
        if body.is_empty() {
            return Ok(serde_json::Value::Null);
        }

        let value: serde_json::Value = serde_json::from_str(&body)?;
        Ok(value)
    }

    async fn handle_bytes_response(resp: reqwest::Response) -> Result<Vec<u8>> {
        let status = resp.status();

        if !status.is_success() {
            let body = resp.text().await?;
            return Err(FalconError::Api(format!(
                "{}: {}",
                status,
                Self::truncate_chars(&body, 200)
            )));
        }

        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    /// Truncate on a char boundary; `String::truncate` panics on
    /// multibyte boundaries, which API error bodies can contain.
    fn truncate_chars(s: &str, max: usize) -> String {
        s.chars().take(max).collect()
    }

    fn is_loopback_http(url: &str) -> bool {
        for prefix in &["http://localhost", "http://127.0.0.1"] {
            if let Some(rest) = url.strip_prefix(prefix) {
                if rest.is_empty() || rest.starts_with(':') || rest.starts_with('/') {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_loopback_http_localhost() {
        assert!(FalconClient::is_loopback_http("http://localhost"));
        assert!(FalconClient::is_loopback_http("http://localhost:8080"));
        assert!(FalconClient::is_loopback_http("http://localhost/path"));
    }

    #[test]
    fn test_is_loopback_http_127_0_0_1() {
        assert!(FalconClient::is_loopback_http("http://127.0.0.1"));
        assert!(FalconClient::is_loopback_http("http://127.0.0.1:9999"));
        assert!(FalconClient::is_loopback_http("http://127.0.0.1/path"));
    }

    #[test]
    fn test_is_loopback_http_rejects_subdomain_bypass() {
        assert!(!FalconClient::is_loopback_http("http://localhost.evil.com"));
        assert!(!FalconClient::is_loopback_http("http://127.0.0.1.evil.com"));
    }

    #[test]
    fn test_truncate_chars_multibyte_boundary() {
        // 100 3-byte chars: byte 200 is not a char boundary.
        let s = "あ".repeat(100);
        let t = FalconClient::truncate_chars(&s, 200);
        assert_eq!(t.chars().count(), 100);
        assert!(FalconClient::truncate_chars(&s, 50).chars().count() == 50);
    }

    #[test]
    fn test_is_loopback_http_rejects_non_loopback() {
        assert!(!FalconClient::is_loopback_http("http://example.com"));
        assert!(!FalconClient::is_loopback_http("https://localhost"));
        assert!(!FalconClient::is_loopback_http("ftp://localhost"));
        assert!(!FalconClient::is_loopback_http(""));
    }
}
