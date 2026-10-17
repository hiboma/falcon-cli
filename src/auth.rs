use crate::config::Config;
use crate::error::{FalconError, Result};
use crate::sanitize::{escape_control_chars, truncate_chars};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Auth {
    config: Config,
    token: Arc<RwLock<Option<String>>>,
    http: reqwest::Client,
}

impl Auth {
    pub fn new(config: Config) -> Result<Self> {
        let url = validate_base_url(&config.base_url)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(url.scheme() == "https")
            .build()?;
        Ok(Self {
            config,
            token: Arc::new(RwLock::new(None)),
            http,
        })
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
            ("grant_type", "client_credentials"),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];
        if let Some(ref cid) = self.config.member_cid {
            params.push(("member_cid", cid.as_str()));
        }

        let resp = self.http.post(&url).form(&params).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = read_response_prefix(resp, MAX_ERROR_BODY_BYTES)
                .await
                .unwrap_or_default();
            let body = escape_control_chars(&truncate_chars(&body, 200));
            return Err(FalconError::Auth(format!("{}: {}", status, body)));
        }

        let token_resp: TokenResponse = resp.json().await?;
        if !token_resp.token_type.eq_ignore_ascii_case("bearer") {
            return Err(FalconError::Auth(format!(
                "unsupported OAuth token_type: {}",
                escape_control_chars(&token_resp.token_type)
            )));
        }
        if token_resp.access_token.is_empty() {
            return Err(FalconError::Auth(
                "OAuth response contained an empty access_token".to_string(),
            ));
        }
        *guard = Some(token_resp.access_token.clone());
        Ok(token_resp.access_token)
    }

    /// Invalidate the cached token so the next request triggers a refresh.
    pub async fn invalidate(&self) {
        let mut guard = self.token.write().await;
        *guard = None;
    }
}

/// Validate the origin used for credential-bearing and Bearer-token requests.
/// HTTPS is mandatory except for loopback HTTP, which is retained for local
/// development and deterministic tests.
pub(crate) fn validate_base_url(base_url: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|e| FalconError::Config(format!("invalid base_url: {}", e)))?;

    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });

    if url.scheme() != "https" && !loopback_http {
        return Err(FalconError::Config(format!(
            "base_url must use HTTPS (got: {}). HTTP is only allowed for loopback hosts.",
            escape_control_chars(base_url)
        )));
    }

    Ok(url)
}

pub(crate) async fn read_response_prefix(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> std::result::Result<String, reqwest::Error> {
    let mut bytes = Vec::with_capacity(max_bytes.min(1024));

    while bytes.len() < max_bytes {
        let Some(chunk) = response.chunk().await? else {
            break;
        };
        let remaining = max_bytes - bytes.len();
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(server: &MockServer) -> Config {
        Config {
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            base_url: server.uri(),
            member_cid: None,
        }
    }

    #[tokio::test]
    async fn sends_client_credentials_grant_type() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "token",
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let token = Auth::new(config(&server))
            .unwrap()
            .get_token()
            .await
            .unwrap();
        assert_eq!(token, "token");
    }

    #[tokio::test]
    async fn rejects_non_bearer_token_type() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "token",
                "token_type": "MAC"
            })))
            .mount(&server)
            .await;

        let error = Auth::new(config(&server))
            .unwrap()
            .get_token()
            .await
            .expect_err("non-Bearer token type must be rejected");
        assert!(error.to_string().contains("unsupported OAuth token_type"));
    }

    #[tokio::test]
    async fn does_not_follow_token_redirects() {
        let destination = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "stolen",
                "token_type": "bearer"
            })))
            .expect(0)
            .mount(&destination)
            .await;

        let source = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("Location", format!("{}/capture", destination.uri())),
            )
            .expect(1)
            .mount(&source)
            .await;

        let error = Auth::new(config(&source))
            .unwrap()
            .get_token()
            .await
            .expect_err("redirect must not be followed");
        assert!(error.to_string().contains("307"));
    }

    #[tokio::test]
    async fn oauth_error_is_bounded_utf8_safe_and_terminal_safe() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(format!("{}\n\u{1b}[31m", "あ".repeat(3_000))),
            )
            .mount(&server)
            .await;

        let message = Auth::new(config(&server))
            .unwrap()
            .get_token()
            .await
            .expect_err("400 must fail")
            .to_string();
        assert!(!message.contains('\n'));
        assert!(!message.contains('\u{1b}'));
        assert!(message.chars().filter(|c| *c == 'あ').count() <= 200);
    }
}
