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
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/sensors/entities/data-feed/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
