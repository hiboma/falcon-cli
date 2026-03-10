use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A request sent from client to daemon over the Unix domain socket.
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonRequest {
    /// Unique request identifier.
    pub id: String,
    /// Authentication token issued at daemon startup.
    pub token: String,
    /// Top-level command name (e.g. "alert", "host").
    pub command: String,
    /// Action name (e.g. "list", "get").
    pub action: String,
    /// Command arguments as key-value pairs.
    #[serde(default)]
    pub args: HashMap<String, serde_json::Value>,
}

/// A response sent from daemon to client over the Unix domain socket.
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonResponse {
    /// Matches the request ID.
    pub id: String,
    /// Status: "ok" or "error".
    pub status: String,
    /// Result data (present when status is "ok").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Error details (present when status is "error").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}

/// Error detail in a daemon response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// Error category (e.g. "auth", "api", "config", "denied", "rate_limited").
    pub kind: String,
    /// Human-readable error message.
    pub message: String,
}

impl DaemonRequest {
    /// Create a new request with a generated UUID and the given token.
    pub fn new(
        token: String,
        command: String,
        action: String,
        args: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            token,
            command,
            action,
            args,
        }
    }
}

impl DaemonResponse {
    /// Create a success response.
    pub fn ok(id: String, data: serde_json::Value) -> Self {
        Self {
            id,
            status: "ok".to_string(),
            data: Some(data),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(id: String, kind: &str, message: String) -> Self {
        Self {
            id,
            status: "error".to_string(),
            data: None,
            error: Some(ErrorDetail {
                kind: kind.to_string(),
                message,
            }),
        }
    }
}

/// Status response for `daemon status` command.
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub socket_path: String,
    pub uptime_seconds: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization_roundtrip() {
        let mut args = HashMap::new();
        args.insert(
            "filter".to_string(),
            serde_json::Value::String("status:'new'".to_string()),
        );
        args.insert("limit".to_string(), serde_json::json!(100));

        let req = DaemonRequest::new(
            "test-token".to_string(),
            "alert".to_string(),
            "list".to_string(),
            args,
        );
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: DaemonRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.command, "alert");
        assert_eq!(deserialized.action, "list");
        assert_eq!(
            deserialized.args.get("filter").unwrap().as_str().unwrap(),
            "status:'new'"
        );
    }

    #[test]
    fn test_response_ok_serialization() {
        let resp = DaemonResponse::ok("test-id".to_string(), serde_json::json!({"resources": []}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("error"));
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_response_error_serialization() {
        let resp = DaemonResponse::error("test-id".to_string(), "api", "not found".to_string());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("data"));
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("not found"));
    }
}
