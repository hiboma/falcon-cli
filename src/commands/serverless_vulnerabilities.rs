use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List serverless deployment IDs
    ///
    /// Response fields:
    ///   resources  - array of deployment ID strings
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
    /// Get serverless deployment details by ID
    ///
    /// Response fields:
    ///   id                    - deployment identifier
    ///   function_name         - serverless function name
    ///   runtime               - function runtime
    ///   vulnerabilities       - list of vulnerabilities
    ///   cloud_provider        - cloud provider name
    ///   created_timestamp     - creation timestamp
    Get {
        /// Deployment ID(s)
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
                "/serverless-vulnerabilities/queries/deployments/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!(
                "/serverless-vulnerabilities/entities/deployments/v1?{}",
                ids.join("&")
            );
            client.get(&path).await
        }
    }
}
