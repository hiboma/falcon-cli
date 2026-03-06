use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List host AIDs
    ///
    /// Response fields:
    ///   resources  - array of host AID strings
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
    /// Get host details by AID
    ///
    /// Response fields:
    ///   device_id             - host agent ID
    ///   hostname              - hostname
    ///   local_ip              - local IP address
    ///   external_ip           - external IP address
    ///   os_version            - operating system version
    ///   platform_name         - platform (Windows, Mac, Linux)
    ///   status                - sensor status
    ///   last_seen             - last seen timestamp
    Get {
        /// Host agent ID(s)
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
                "/devices/queries/devices/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/devices/entities/devices/v2?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
