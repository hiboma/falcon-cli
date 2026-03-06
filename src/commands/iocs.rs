use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List legacy IOC IDs
    ///
    /// Response fields:
    ///   resources  - array of IOC ID strings
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
    /// Get legacy IOC details by ID
    ///
    /// Response fields:
    ///   id                    - IOC identifier
    ///   type                  - IOC type (domain, ipv4, sha256, etc.)
    ///   value                 - IOC value
    ///   policy                - applied policy (detect, none)
    ///   share_level           - share level (red, white, etc.)
    ///   expiration_days       - days until expiration
    ///   source                - IOC source
    ///   description           - IOC description
    Get {
        /// IOC ID(s)
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
                "/indicators/queries/iocs/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/indicators/entities/iocs/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
