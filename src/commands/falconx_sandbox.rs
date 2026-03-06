use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List Falcon Intelligence Sandbox submission IDs
    ///
    /// Response fields:
    ///   resources  - array of submission ID strings
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
    /// Get Falcon Intelligence Sandbox submission details by ID
    ///
    /// Response fields:
    ///   id                    - submission identifier
    ///   state                 - submission state
    ///   created_timestamp     - creation timestamp
    ///   sandbox               - sandbox analysis results
    ///   verdict               - analysis verdict
    ///   ioc_report_strict_csv_artifact_id - IOC report artifact ID
    ///   ioc_report_broad_csv_artifact_id  - broad IOC report artifact ID
    Get {
        /// Submission ID(s)
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
                "/falconx/queries/submissions/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/falconx/entities/submissions/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
