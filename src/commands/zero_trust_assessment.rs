use clap::Subcommand;

use crate::client::FalconClient;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Get Zero Trust Assessment for hosts
    ///
    /// Response fields:
    ///   id                    - host identifier
    ///   assessment            - zero trust assessment details
    ///   overall_score         - overall assessment score
    ///   sensor_file_status    - sensor file status score
    ///   os_signal             - OS signal score
    Get {
        /// Host ID(s)
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,
    },
}

pub async fn execute(client: &FalconClient, action: Action) -> Result<serde_json::Value> {
    match action {
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!(
                "/zero-trust-assessment/entities/assessments/v1?{}",
                ids.join("&")
            );
            client.get(&path).await
        }
    }
}
