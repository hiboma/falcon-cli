use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::{FalconError, Result};

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Get a lead and its related detections in one step
    ///
    /// This is a falcon-cli extended command that combines multiple API calls.
    /// It does not map to a single Falcon API endpoint.
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
    Get {
        /// Automated-lead composite ID (e.g. "<cid>:automated-lead:<cid>:<lead_id>")
        #[arg(long, required = true)]
        id: String,
    },
}

pub async fn execute(client: &FalconClient, action: Action) -> Result<serde_json::Value> {
    match action {
        Action::Get { id } => {
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
