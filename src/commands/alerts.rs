use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::{FalconError, Result};

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List alert IDs
    ///
    /// Returns alert composite IDs matching the specified filter criteria.
    /// Use these IDs with the `get` subcommand to retrieve full alert details.
    ///
    /// FQL filter examples:
    ///   --filter "type:'automated-lead'"            Automated Lead alerts only
    ///   --filter "aggregate_id:'<id>'"              Detections linked to a lead
    ///   --filter "status:'new'"                     Alerts with status new
    ///   --filter "status:'closed'"                  Alerts with status closed
    ///   --filter "severity:>=60"                    Severity >= 60
    ///   --filter "device.device_id:'<device_id>'"   Alerts for a specific device
    ///   --filter "type:'automated-lead'+status:'new'"  Combine with + (AND)
    ///
    /// Response fields:
    ///   resources  - array of alert composite ID strings
    ///   errors     - array of error objects (if any)
    List {
        /// FQL filter expression (e.g. "type:'automated-lead'", "aggregate_id:'<id>'")
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
    /// Composite ID formats:
    ///   automated-lead:  <cid>:automated-lead:<cid>:<lead_id>
    ///   detection (ind): <cid>:ind:<device_id>:<process_id>-<pattern_id>-<offset>
    ///
    /// Response fields:
    ///   composite_id      - unique alert composite identifier
    ///   type              - alert type (e.g. "automated-lead")
    ///   aggregate_id      - links lead and its detections (use with list --filter)
    ///   status            - alert status
    ///   severity          - alert severity
    ///   tactic            - MITRE ATT&CK tactic
    ///   technique         - MITRE ATT&CK technique
    ///   device.device_id  - device identifier
    ///   created_timestamp - alert creation timestamp
    ///   updated_timestamp - alert update timestamp
    Get {
        /// Alert composite ID(s) (e.g. "<cid>:automated-lead:<cid>:<lead_id>")
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,
    },
    /// Investigate a lead and its related detections in one step
    ///
    /// Retrieves the lead details, finds all related detections via
    /// aggregate_id, and returns everything in a single JSON response.
    ///
    /// This automates the manual workflow:
    ///   1. alert get --id <composite_id>
    ///   2. Copy aggregate_id from the response
    ///   3. alert list --filter "aggregate_id:'<aggregate_id>'"
    ///   4. alert get --id <detection_id_1> <detection_id_2> ...
    ///
    /// Output format:
    ///   { "lead": { ... }, "detections": [ ... ] }
    Investigate {
        /// Alert composite ID to investigate
        #[arg(long, required = true)]
        id: String,
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
        Action::Investigate { id } => {
            // Step 1: Get lead details
            let body = serde_json::json!({ "composite_ids": [&id] });
            let lead_response = client.post("/alerts/entities/alerts/v2", &body).await?;

            // Step 2: Extract aggregate_id
            let aggregate_id = lead_response["resources"][0]["aggregate_id"]
                .as_str()
                .ok_or_else(|| {
                    FalconError::Api("aggregate_id not found in alert response".to_string())
                })?;

            // Step 3: Find related detection IDs via aggregate_id
            let filter = format!("aggregate_id:'{}'", aggregate_id);
            let path = build_query_path("/alerts/queries/alerts/v2", Some(&filter), 100, None);
            let list_response = client.get(&path).await?;

            let detection_ids: Vec<String> = list_response["resources"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .filter(|did| *did != id)
                .collect();

            // Step 4: Get detection details
            let detections = if detection_ids.is_empty() {
                serde_json::json!([])
            } else {
                let det_body = serde_json::json!({ "composite_ids": detection_ids });
                let det_response = client.post("/alerts/entities/alerts/v2", &det_body).await?;
                det_response["resources"].clone()
            };

            // Step 5: Return combined result
            Ok(serde_json::json!({
                "lead": lead_response["resources"][0],
                "detections": detections
            }))
        }
    }
}
