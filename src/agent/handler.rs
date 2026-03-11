use crate::agent::protocol::{AgentRequest, AgentResponse};
use crate::agent::security::{AuditLog, CommandWhitelist, RateLimiter};
use crate::dispatch;
use clap::Parser;
use std::sync::Arc;
use std::time::Instant;

/// Handles agent requests by dispatching to the appropriate command.
pub struct RequestHandler {
    falcon_client: Arc<crate::client::FalconClient>,
    whitelist: Arc<CommandWhitelist>,
    rate_limiter: Arc<RateLimiter>,
    session_token: String,
}

impl RequestHandler {
    pub fn new(
        falcon_client: Arc<crate::client::FalconClient>,
        whitelist: Arc<CommandWhitelist>,
        rate_limiter: Arc<RateLimiter>,
        session_token: String,
    ) -> Self {
        Self {
            falcon_client,
            whitelist,
            rate_limiter,
            session_token,
        }
    }

    /// Process a single request and return a response.
    pub async fn handle(&self, request: AgentRequest) -> AgentResponse {
        let start = Instant::now();

        AuditLog::log_request(&request.command, &request.action, &request.id);

        // Verify session token using constant-time comparison to prevent timing attacks.
        if !constant_time_eq(request.token.as_bytes(), self.session_token.as_bytes()) {
            AuditLog::log_denied(&request.id, "invalid_token");
            return AgentResponse::error(request.id, "auth", "invalid session token".to_string());
        }

        // Check rate limit.
        if !self.rate_limiter.try_acquire() {
            AuditLog::log_denied(&request.id, "rate_limited");
            return AgentResponse::error(
                request.id,
                "rate_limited",
                "rate limit exceeded".to_string(),
            );
        }

        // Validate command and action names.
        if !is_valid_name(&request.command) || !is_valid_name(&request.action) {
            AuditLog::log_denied(&request.id, "invalid_command_name");
            return AgentResponse::error(
                request.id,
                "validation",
                "invalid command or action name".to_string(),
            );
        }

        // Check whitelist.
        if !self.whitelist.is_allowed(&request.command, &request.action) {
            AuditLog::log_denied(&request.id, "command_not_allowed");
            return AgentResponse::error(
                request.id,
                "denied",
                format!(
                    "command '{}:{}' is not in the allowed list",
                    request.command, request.action,
                ),
            );
        }

        // Build CLI args and dispatch.
        let result = self.dispatch_command(&request).await;

        let duration = start.elapsed().as_millis();

        match result {
            Ok(value) => {
                AuditLog::log_response(&request.id, "ok", duration);
                AgentResponse::ok(request.id, value)
            }
            Err(e) => {
                let (kind, message) = classify_error(&e);
                AuditLog::log_response(&request.id, &kind, duration);
                AgentResponse::error(request.id, &kind, message)
            }
        }
    }

    /// Dispatch a request to the appropriate command by reconstructing CLI args
    /// and parsing them with clap.
    async fn dispatch_command(
        &self,
        request: &AgentRequest,
    ) -> crate::error::Result<serde_json::Value> {
        // Build a synthetic CLI argument vector from the request.
        let mut args_vec: Vec<String> = vec![
            "falcon-cli".to_string(),
            request.command.clone(),
            request.action.clone(),
        ];

        // Convert args map to CLI-style arguments.
        for (key, value) in &request.args {
            let flag = format!("--{}", key);
            match value {
                serde_json::Value::Null => {}
                serde_json::Value::Bool(b) => {
                    if *b {
                        args_vec.push(flag);
                    }
                }
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        args_vec.push(flag.clone());
                        args_vec.push(item_to_string(item));
                    }
                }
                _ => {
                    args_vec.push(flag);
                    args_vec.push(item_to_string(value));
                }
            }
        }

        // Parse with clap to get a Command.
        let cli = match crate::cli::Cli::try_parse_from(&args_vec) {
            Ok(c) => c,
            Err(e) => {
                return Err(crate::error::FalconError::Config(format!(
                    "invalid command arguments: {}",
                    e
                )));
            }
        };

        dispatch::execute(&self.falcon_client, cli.command).await
    }
}

fn item_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validate that a command/action name contains only safe characters.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn classify_error(err: &crate::error::FalconError) -> (String, String) {
    // Log full error details server-side, return generic messages to client.
    eprintln!("agent: command error: {}", err);
    match err {
        crate::error::FalconError::Auth(_) => {
            ("auth".to_string(), "authentication failed".to_string())
        }
        crate::error::FalconError::Api(msg) => ("api".to_string(), msg.clone()),
        crate::error::FalconError::Http(_) => {
            ("http".to_string(), "HTTP request failed".to_string())
        }
        crate::error::FalconError::Json(_) => {
            ("json".to_string(), "response parsing failed".to_string())
        }
        crate::error::FalconError::Config(msg) => ("config".to_string(), msg.clone()),
    }
}
