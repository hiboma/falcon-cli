use clap::Subcommand;

use crate::client::FalconClient;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List ThreatGraph edge types
    ///
    /// Response fields:
    ///   resources  - array of edge type strings
    ///   errors     - array of error objects (if any)
    List,
    /// Get ThreatGraph vertex details by vertex type and ID
    ///
    /// Response fields:
    ///   id                    - vertex identifier
    ///   vertex_type           - type of vertex
    ///   properties            - vertex properties
    ///   edges                 - connected edges
    ///   scope                 - vertex scope
    Get {
        /// Vertex type
        #[arg(long, required = true)]
        vertex_type: String,

        /// Vertex ID(s)
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,
    },
}

pub async fn execute(client: &FalconClient, action: Action) -> Result<serde_json::Value> {
    match action {
        Action::List => client.get("/threatgraph/queries/edge-types/v1").await,
        Action::Get { vertex_type, id } => {
            let ids = id
                .iter()
                .map(|i| format!("ids={}", i))
                .collect::<Vec<String>>()
                .join("&");
            let path = format!(
                "/threatgraph/entities/vertices/v1?vertex_type={}&{}",
                vertex_type, ids
            );
            client.get(&path).await
        }
    }
}
