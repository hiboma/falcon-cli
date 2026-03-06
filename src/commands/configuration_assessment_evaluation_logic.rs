use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List configuration assessment evaluation logic IDs
    ///
    /// Response fields:
    ///   resources  - array of evaluation logic ID strings
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
    /// Get configuration assessment evaluation logic details by ID
    ///
    /// Response fields:
    ///   id                    - evaluation logic identifier
    ///   title                 - logic title
    ///   description           - logic description
    ///   platform              - target platform
    ///   severity              - severity level
    ///   created_timestamp     - creation timestamp
    Get {
        /// Evaluation logic ID(s)
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
                "/configuration-assessment/queries/evaluation-logic/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!(
                "/configuration-assessment/entities/evaluation-logic/v1?{}",
                ids.join("&")
            );
            client.get(&path).await
        }
    }
}
