use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List detection IDs
    ///
    /// Response fields:
    ///   resources  - array of detection ID strings
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
    /// Get detection details by ID
    ///
    /// Response fields:
    ///   detection_id          - unique detection identifier
    ///   status                - detection status
    ///   max_severity_displayname - severity display name
    ///   first_behavior        - timestamp of first behavior
    ///   last_behavior         - timestamp of last behavior
    Get {
        /// Detection ID(s)
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
                "/detects/queries/detects/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let body = serde_json::json!({ "ids": id });
            client
                .post("/detects/entities/summaries/GET/v1", &body)
                .await
        }
    }
}
