use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List Discover host IDs
    ///
    /// Response fields:
    ///   resources  - array of host ID strings
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
    /// Get Discover host details by ID
    ///
    /// Response fields:
    ///   id                    - host identifier
    ///   hostname              - hostname
    ///   local_ip_addresses    - local IP addresses
    ///   os_version            - operating system version
    ///   platform_name         - platform name
    ///   discoverer_aids       - AIDs that discovered the host
    ///   first_seen_timestamp  - first seen timestamp
    Get {
        /// Host ID(s)
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
                "/discover/queries/hosts/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/discover/entities/hosts/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
