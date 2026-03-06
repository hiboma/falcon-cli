use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List real-time response session IDs
    ///
    /// Response fields:
    ///   resources  - array of session ID strings
    ///   errors     - array of error objects (if any)
    List {
        /// FQL filter expression
        #[arg(long)]
        filter: Option<String>,

        /// Maximum number of results
        #[arg(long, default_value = "100")]
        limit: u32,

        /// Pagination offset
        #[arg(long)]
        offset: Option<String>,
    },
    /// Get real-time response session details by ID
    ///
    /// Response fields:
    ///   session_id            - unique session identifier
    ///   aid                   - host agent ID
    ///   hostname              - hostname
    ///   commands              - array of commands executed
    ///   created_at            - session creation timestamp
    ///   updated_at            - session update timestamp
    Get {
        /// Session ID(s)
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,
    },
}

pub async fn execute(client: &FalconClient, action: Action) -> Result<serde_json::Value> {
    match action {
        Action::List {
            filter,
            limit,
            offset,
        } => {
            let path = build_query_path(
                "/real-time-response/queries/sessions/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let body = serde_json::json!({ "ids": id });
            client
                .post("/real-time-response/entities/sessions/GET/v1", &body)
                .await
        }
    }
}
