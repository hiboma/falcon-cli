use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List incident IDs
    ///
    /// Response fields:
    ///   resources  - array of incident ID strings
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
    /// Get incident details by ID
    ///
    /// Response fields:
    ///   incident_id           - unique incident identifier
    ///   status                - incident status
    ///   fine_score            - incident severity score
    ///   host_ids              - array of associated host AIDs
    ///   created               - incident creation timestamp
    ///   start                 - incident start timestamp
    ///   end                   - incident end timestamp
    Get {
        /// Incident ID(s)
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
                "/incidents/queries/incidents/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let body = serde_json::json!({ "ids": id });
            client
                .post("/incidents/entities/incidents/GET/v1", &body)
                .await
        }
    }
}
