use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List MalQuery request IDs
    ///
    /// Note: MalQuery uses request IDs to track search results.
    /// Use this to query existing request IDs.
    ///
    /// Response fields:
    ///   resources  - array of request ID strings
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
    /// Get MalQuery request details by ID
    ///
    /// Response fields:
    ///   id                    - request identifier
    ///   status                - request status (inprogress, done, failed)
    ///   created_timestamp     - creation timestamp
    ///   updated_timestamp     - last update timestamp
    ///   user_id               - requesting user identifier
    ///   resources             - array of matching sample objects
    Get {
        /// Request ID(s)
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
                "/malquery/queries/exact-search/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/malquery/entities/requests/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
