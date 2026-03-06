use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List quarantined file IDs
    ///
    /// Response fields:
    ///   resources  - array of quarantined file ID strings
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
    /// Get quarantined file details by ID
    ///
    /// Response fields:
    ///   id                    - quarantined file identifier
    ///   hostname              - host where file was quarantined
    ///   sha256                - SHA-256 hash of the file
    ///   paths                 - array of file paths
    ///   state                 - quarantine state
    ///   date_created          - quarantine creation timestamp
    ///   date_updated          - quarantine update timestamp
    Get {
        /// Quarantined file ID(s)
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
                "/quarantine/queries/quarantined-files/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let body = serde_json::json!({ "ids": id });
            client
                .post("/quarantine/entities/quarantined-files/GET/v1", &body)
                .await
        }
    }
}
