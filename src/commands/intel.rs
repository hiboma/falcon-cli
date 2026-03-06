use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List threat actor IDs
    ///
    /// Response fields:
    ///   resources  - array of actor ID strings
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
    /// Get threat actor details by ID
    ///
    /// Response fields:
    ///   id                    - actor identifier
    ///   name                  - actor name
    ///   slug                  - actor slug
    ///   known_as              - alternative names
    ///   origins               - actor origin countries
    ///   target_countries      - targeted countries
    ///   target_industries     - targeted industries
    ///   motivations           - actor motivations
    ///   first_activity_date   - first observed activity date
    ///   last_activity_date    - last observed activity date
    Get {
        /// Actor ID(s)
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
                "/intel/queries/actors/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/intel/entities/actors/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
