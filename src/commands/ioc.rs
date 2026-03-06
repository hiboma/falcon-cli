use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List IOC indicator IDs
    ///
    /// Response fields:
    ///   resources  - array of indicator ID strings
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
    /// Get IOC indicator details by ID
    ///
    /// Response fields:
    ///   id                    - indicator identifier
    ///   type                  - indicator type (domain, ipv4, sha256, etc.)
    ///   value                 - indicator value
    ///   action                - action to take (detect, prevent, etc.)
    ///   severity              - indicator severity
    ///   platforms             - applicable platforms
    ///   expiration            - expiration timestamp
    ///   description           - indicator description
    ///   created_on            - creation timestamp
    ///   modified_on           - last modification timestamp
    Get {
        /// Indicator ID(s)
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
                "/iocs/queries/indicators/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/iocs/entities/indicators/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
