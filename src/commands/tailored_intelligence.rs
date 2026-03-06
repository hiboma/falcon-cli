use clap::Subcommand;

use crate::client::FalconClient;
use crate::commands::build_query_path;
use crate::error::Result;

#[derive(Subcommand, Debug)]
pub enum Action {
    /// List Tailored Intelligence report IDs
    ///
    /// TODO: エンドポイントパスが不確かなため、正式な API ドキュメントで確認が必要です。
    ///
    /// Response fields:
    ///   resources  - array of report ID strings
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
    /// Get Tailored Intelligence report details by ID
    ///
    /// TODO: エンドポイントパスが不確かなため、正式な API ドキュメントで確認が必要です。
    ///
    /// Response fields:
    ///   id                    - report identifier
    ///   name                  - report name
    ///   description           - report description
    ///   type                  - report type
    ///   created_date          - creation date
    ///   last_modified_date    - last modification date
    ///   tags                  - associated tags
    Get {
        /// Report ID(s)
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
            // TODO: エンドポイントパスが不確かです。正式な API ドキュメントで確認してください。
            let path = build_query_path(
                "/ti/queries/reports/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            // TODO: エンドポイントパスが不確かです。正式な API ドキュメントで確認してください。
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/ti/entities/reports/v1?{}", ids.join("&"));
            client.get(&path).await
        }
    }
}
