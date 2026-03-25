use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Query report execution IDs
    ///
    /// Response fields:
    ///   resources  - array of report execution ID strings
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
    /// Get report execution details by ID
    ///
    /// Response fields:
    ///   id         - report execution identifier
    ///   status     - execution status
    ///   created_on - execution creation timestamp
    ///   report_id  - associated report identifier
    Get {
        /// Report execution ID(s)
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,
    },
    /// Download report execution result
    ///
    /// Downloads the report data (typically gzip-compressed CSV) for a given
    /// report execution ID. Writes to a file or stdout.
    Download {
        /// Report execution ID
        #[arg(long, required = true)]
        id: String,

        /// Output file path (default: stdout)
        #[arg(long, short)]
        output: Option<String>,
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
                "/reports/queries/report-executions/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/reports/entities/report-executions/v1?{}", ids.join("&"));
            client.get(&path).await
        }
        Action::Download { id, output } => {
            let path = format!("/reports/entities/report-executions-download/v1?ids={}", id);
            let data = client.get_bytes(&path).await?;
            let encoded = STANDARD.encode(&data);

            Ok(serde_json::json!({
                "_binary": true,
                "data": encoded,
                "bytes": data.len(),
                "output": output,
            }))
        }
    }
}
