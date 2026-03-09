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
    /// Update alert status and add comments
    ///
    /// Uses PATCH /alerts/entities/alerts/v3 to update alerts.
    ///
    /// Examples:
    ///   alert update --id <composite_id> --status closed --comment "false positive"
    ///   alert update --id <id1> <id2> --status closed --comment "resolved"
    Update {
        /// Alert composite ID(s) to update
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,

        /// New status (e.g. "new", "in_progress", "closed")
        #[arg(long)]
        status: Option<String>,

        /// Comment to add
        #[arg(long)]
        comment: Option<String>,
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
        Action::Update {
            id,
            status,
            comment,
        } => {
            let mut action_parameters = Vec::new();
            if let Some(s) = status {
                action_parameters.push(serde_json::json!({"name": "update_status", "value": s}));
            }
            if let Some(c) = comment {
                action_parameters.push(serde_json::json!({"name": "append_comment", "value": c}));
            }
            let body = serde_json::json!({
                "composite_ids": id,
                "action_parameters": action_parameters,
            });
            client.patch("/alerts/entities/alerts/v3", &body).await
        }
    }
}
