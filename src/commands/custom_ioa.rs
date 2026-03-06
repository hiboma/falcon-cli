use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List Custom IOA rule IDs
    ///
    /// Response fields:
    ///   resources  - array of rule ID strings
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
    /// Get Custom IOA rule details by ID
    ///
    /// Response fields:
    ///   instance_id           - rule instance identifier
    ///   name                  - rule name
    ///   description           - rule description
    ///   pattern_id            - pattern identifier
    ///   pattern_severity      - pattern severity
    ///   ruletype_id           - rule type identifier
    ///   ruletype_name         - rule type name
    ///   enabled               - whether the rule is enabled
    ///   created_on            - creation timestamp
    ///   modified_on           - last modification timestamp
    Get {
        /// Rule ID(s)
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
                "/ioarules/queries/rules/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/ioarules/entities/rules/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
