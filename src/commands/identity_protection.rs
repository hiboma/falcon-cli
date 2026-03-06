use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List Identity Protection entity IDs
    ///
    /// Response fields:
    ///   resources  - array of entity ID strings
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
    /// Get Identity Protection entity details by ID
    ///
    /// Response fields:
    ///   id                    - entity identifier
    ///   entity_type           - type of entity
    ///   primary_display_name  - display name
    ///   risk_score            - risk score
    ///   accounts              - associated accounts
    ///   created_timestamp     - creation timestamp
    Get {
        /// Entity ID(s)
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
                "/identity-protection/queries/entities/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!(
                "/identity-protection/entities/entities/v1?{}",
                ids.join("&")
            );
            client.get(&path).await
        }
    }
}
