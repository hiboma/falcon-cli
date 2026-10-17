use clap::Subcommand;

use crate::client::FalconClient;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List event stream IDs
    ///
    /// Note: Requires an appId parameter to identify the consuming application.
    ///
    /// Response fields:
    ///   resources  - array of event stream objects
    ///   errors     - array of error objects (if any)
    List {
        /// Application ID for the data feed consumer
        #[arg(long)]
        app_id: Option<String>,

        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: Option<String>,
    },
    /// Get event stream details by ID
    ///
    /// Response fields:
    ///   id                    - stream identifier
    ///   data_feed_url         - URL to consume events
    ///   session_token         - session token for authentication
    ///   refresh_active_session_interval - refresh interval in seconds
    Get {
        /// Stream ID(s)
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,

        /// Include session_token values in output and agent IPC
        #[arg(long)]
        show_secrets: bool,
    },
}

pub async fn execute(client: &FalconClient, action: Action) -> Result<serde_json::Value> {
    match action {
        Action::List { app_id, offset } => {
            let mut params: Vec<String> = Vec::new();
            if let Some(app_id) = app_id {
                params.push(format!("appId={}", app_id));
            }
            if let Some(offset) = offset {
                params.push(format!("offset={}", offset));
            }
            let path = if params.is_empty() {
                "/sensors/queries/data-feed/v1".to_string()
            } else {
                format!("/sensors/queries/data-feed/v1?{}", params.join("&"))
            };
            client.get(&path).await
        }
        Action::Get { id, show_secrets } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/sensors/entities/data-feed/v1?{}", ids.join("&"));
            let mut response = client.get(&path).await?;
            if !show_secrets {
                redact_session_tokens(&mut response);
            }
            Ok(response)
        }
    }
}

fn redact_session_tokens(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let normalized_key: String = key
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect();
                if normalized_key == "sessiontoken" {
                    *value = serde_json::Value::String("***".to_string());
                } else {
                    redact_session_tokens(value);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_session_tokens(value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_nested_session_tokens_without_changing_other_fields() {
        let mut value = serde_json::json!({
            "resources": [{
                "session_token": "secret",
                "sessionToken": "camel-secret",
                "Session-Token": "mixed-secret",
                "nested": {"session_token": "another", "id": "stream-id"}
            }]
        });

        redact_session_tokens(&mut value);

        assert_eq!(value["resources"][0]["session_token"], "***");
        assert_eq!(value["resources"][0]["sessionToken"], "***");
        assert_eq!(value["resources"][0]["Session-Token"], "***");
        assert_eq!(value["resources"][0]["nested"]["session_token"], "***");
        assert_eq!(value["resources"][0]["nested"]["id"], "stream-id");
    }
}
