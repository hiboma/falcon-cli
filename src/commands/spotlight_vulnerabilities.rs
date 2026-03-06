use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List Spotlight vulnerability IDs
    ///
    /// Response fields:
    ///   resources  - array of vulnerability ID strings
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
    /// Get Spotlight vulnerability details by ID
    ///
    /// Response fields:
    ///   id                    - vulnerability identifier
    ///   cve                   - CVE information
    ///   host_info             - affected host details
    ///   remediation           - remediation guidance
    ///   status                - vulnerability status
    ///   created_timestamp     - creation timestamp
    Get {
        /// Vulnerability ID(s)
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
                "/spotlight/queries/vulnerabilities/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/spotlight/entities/vulnerabilities/v2?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
