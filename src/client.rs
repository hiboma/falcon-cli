use crate::auth::{read_response_prefix, validate_base_url, Auth};
use crate::error::{FalconError, Result};
use crate::sanitize::{escape_control_chars, truncate_chars};
use reqwest::StatusCode;

const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub struct FalconClient {
    auth: Auth,
    http: reqwest::Client,
    base_url: String,
}

impl FalconClient {
    pub fn new(auth: Auth, base_url: String) -> Result<Self> {
        let url = validate_base_url(&base_url)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(url.scheme() == "https")
            .build()?;
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
        if !status.is_success() {
            let body = read_response_prefix(resp, MAX_ERROR_BODY_BYTES).await?;
            return Err(FalconError::Api(format!(
                "{}: {}",
                status,
                escape_control_chars(&truncate_chars(&body, 200))
            )));
        }

        let body = resp.text().await?;

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
            let body = read_response_prefix(resp, MAX_ERROR_BODY_BYTES).await?;
            return Err(FalconError::Api(format!(
                "{}: {}",
                status,
                escape_control_chars(&truncate_chars(&body, 200))
            )));
        }

        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_loopback_http_localhost() {
        assert!(validate_base_url("http://localhost").is_ok());
        assert!(validate_base_url("http://localhost:8080").is_ok());
        assert!(validate_base_url("http://localhost/path").is_ok());
    }

    #[test]
    fn test_is_loopback_http_127_0_0_1() {
        assert!(validate_base_url("http://127.0.0.1").is_ok());
        assert!(validate_base_url("http://127.0.0.1:9999").is_ok());
        assert!(validate_base_url("http://127.0.0.1/path").is_ok());
        assert!(validate_base_url("http://[::1]:9999/path").is_ok());
    }

    #[test]
    fn test_is_loopback_http_rejects_subdomain_bypass() {
        assert!(validate_base_url("http://localhost.evil.com").is_err());
        assert!(validate_base_url("http://127.0.0.1.evil.com").is_err());
    }

    #[test]
    fn test_truncate_chars_multibyte_boundary() {
        // 100 3-byte chars: byte 200 is not a char boundary.
        let s = "あ".repeat(100);
        let t = truncate_chars(&s, 200);
        assert_eq!(t.chars().count(), 100);
        assert!(truncate_chars(&s, 50).chars().count() == 50);
    }

    #[test]
    fn test_is_loopback_http_rejects_non_loopback() {
        assert!(validate_base_url("http://example.com").is_err());
        assert!(validate_base_url("https://localhost").is_ok());
        assert!(validate_base_url("ftp://localhost").is_err());
        assert!(validate_base_url("").is_err());
    }

    #[tokio::test]
    async fn test_delete_accepts_empty_204_body() {
        let server = wiremock::MockServer::start().await;
        let client = test_support::mock_client(&server).await;

        wiremock::Mock::given(wiremock::matchers::method("DELETE"))
            .and(wiremock::matchers::path("/some/resource"))
            .respond_with(wiremock::ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let value = client
            .delete("/some/resource")
            .await
            .expect("204 is success");
        assert_eq!(value, serde_json::Value::Null);
    }

    #[tokio::test]
    async fn test_error_body_is_truncated_on_char_boundary() {
        let server = wiremock::MockServer::start().await;
        let client = test_support::mock_client(&server).await;

        // 300 3-byte chars: a byte-based truncate(200) would panic here.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/fails"))
            .respond_with(wiremock::ResponseTemplate::new(500).set_body_string("あ".repeat(300)))
            .mount(&server)
            .await;

        let err = client.get("/fails").await.expect_err("500 is an error");
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.chars().filter(|c| *c == 'あ').count() == 200);
    }
}

/// Shared helpers for wiremock-backed tests in this crate.
#[cfg(test)]
pub(crate) mod test_support {
    use super::FalconClient;
    use crate::auth::Auth;
    use crate::config::Config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a `FalconClient` against a wiremock server with the OAuth2
    /// token endpoint stubbed out.
    pub(crate) async fn mock_client(server: &MockServer) -> FalconClient {
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-token",
                "token_type": "bearer",
                "expires_in": 1799,
            })))
            .mount(server)
            .await;

        let config = Config {
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            base_url: server.uri(),
            member_cid: None,
        };
        let auth = Auth::new(config).expect("loopback http auth");
        FalconClient::new(auth, server.uri()).expect("loopback http client")
    }
}
