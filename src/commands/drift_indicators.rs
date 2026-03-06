use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List drift indicator IDs
    ///
    /// Response fields:
    ///   resources  - array of drift indicator ID strings
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
    /// Get drift indicator details by ID
    ///
    /// Response fields:
    ///   id                    - drift indicator identifier
    ///   container_id          - associated container ID
    ///   indicator_type        - type of drift indicator
    ///   severity              - severity level
    ///   created_timestamp     - creation timestamp
    Get {
        /// Drift indicator ID(s)
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
                "/container-security/queries/drift-indicators/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!(
                "/container-security/entities/drift-indicators/v1?{}",
                ids.join("&")
            );
            client.get(&path).await
        }
    }
}
