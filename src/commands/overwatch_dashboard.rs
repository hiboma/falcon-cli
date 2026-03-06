use clap::Subcommand;

use crate::client::FalconClient;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Get OverWatch events aggregate
    ///
    /// Sends a POST request to retrieve aggregated OverWatch event data.
    ///
    /// Response fields:
    ///   resources  - array of aggregated event objects
    ///   errors     - array of error objects (if any)
    Get,
}

pub async fn execute(client: &FalconClient, action: Action) -> Result<serde_json::Value> {
    match action {
        Action::Get => {
            client
                .post(
                    "/overwatch-dashboards/aggregates/events/GET/v1",
                    &serde_json::json!([]),
                )
                .await
        }
    }
}
