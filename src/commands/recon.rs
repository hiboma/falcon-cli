use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List Recon monitoring rule IDs
    ///
    /// Response fields:
    ///   resources  - array of rule ID strings
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
    /// Get Recon monitoring rule details by ID
    ///
    /// Response fields:
    ///   id                    - rule identifier
    ///   name                  - rule name
    ///   filter               - rule filter expression
    ///   priority              - rule priority (high, medium, low)
    ///   permissions           - rule permissions
    ///   topic                 - monitoring topic
    ///   status                - rule status (active, inactive)
    ///   created_timestamp     - creation timestamp
    ///   last_updated_timestamp - last update timestamp
    Get {
        /// Rule ID(s)
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
                "/recon/queries/rules/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/recon/entities/rules/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
