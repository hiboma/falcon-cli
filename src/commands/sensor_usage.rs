use clap::Subcommand;

use crate::client::FalconClient;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Get weekly average sensor usage
    Get,
}

pub async fn execute(client: &FalconClient, action: Action) -> Result<serde_json::Value> {
    match action {
        Action::Get => {
            client
                .get("/billing-dashboards-usage/aggregates/weekly-average/v1")
                .await
        }
    }
}
