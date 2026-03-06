use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List alert IDs
    ///
    /// Response fields:
    ///   resources  - array of alert ID strings
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
    /// Get alert details by composite ID
    ///
    /// Response fields:
    ///   composite_id          - unique alert composite identifier
    ///   status                - alert status
    ///   severity              - alert severity
    ///   tactic                - MITRE ATT&CK tactic
    ///   technique             - MITRE ATT&CK technique
    ///   created_timestamp     - alert creation timestamp
    ///   updated_timestamp     - alert update timestamp
    Get {
        /// Alert composite ID(s)
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
                "/alerts/queries/alerts/v2",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let body = serde_json::json!({ "composite_ids": id });
            client.post("/alerts/entities/alerts/v2", &body).await
        }
    }
}
