use clap::Subcommand;

use crate::client::FalconClient;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Get delivery settings
    ///
    /// Response fields:
    ///   resources  - delivery settings configuration
    ///   errors     - array of error objects (if any)
    Get,
}

pub async fn execute(client: &FalconClient, action: Action) -> Result<serde_json::Value> {
    match action {
        Action::Get => {
            client
                .get("/delivery-settings/entities/delivery-settings/v1")
                .await
        }
    }
}
