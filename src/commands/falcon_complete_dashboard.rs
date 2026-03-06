use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List Falcon Complete Dashboard allowlist IDs
    ///
    /// Response fields:
    ///   resources  - array of allowlist entry ID strings
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
    /// Get Falcon Complete Dashboard allowlist entry details by ID
    ///
    /// Response fields:
    ///   id                    - allowlist entry identifier
    ///   name                  - entry name
    ///   description           - entry description
    ///   created_by            - creator
    ///   created_timestamp     - creation timestamp
    Get {
        /// Allowlist entry ID(s)
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
                "/falcon-complete-dashboards/queries/allowlist/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!(
                "/falcon-complete-dashboards/entities/allowlist/v1?{}",
                ids.join("&")
            );
            client.get(&path).await
        }
    }
}
