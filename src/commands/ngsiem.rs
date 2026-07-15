use std::time::{Duration, Instant};

use clap::Subcommand;
use serde_json::json;

use crate::client::FalconClient;
use crate::commands::{build_query_path, encode};
use crate::error::{FalconError, Result};

const SEARCH_POLL_INTERVAL: Duration = Duration::from_millis(1000);

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Query NGSIEM rule IDs
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
    /// Get NGSIEM rule details
    Get {
        /// NGSIEM rule ID(s)
        #[arg(long, required = true, num_args = 1..)]
        id: Vec<String>,
    },
    /// Run a CQL search (Advanced event search) and wait for results
    Search {
        /// CQL query string
        #[arg(long)]
        query: String,

        /// Repository or view to search
        #[arg(long, default_value = "search-all")]
        repository: String,

        /// Start of the time range (relative like "1h", "7d", or epoch millis)
        #[arg(long, default_value = "1h")]
        start: String,

        /// End of the time range (relative or epoch millis; defaults to now)
        #[arg(long)]
        end: Option<String>,

        /// Seconds to wait for the search to complete
        #[arg(long, default_value = "60")]
        timeout: u64,
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
                "/ngsiem/queries/rules/v1",
                filter.as_deref(),
                limit,
                offset.as_deref(),
            );
            client.get(&path).await
        }
        Action::Get { id } => {
            let ids: Vec<String> = id.iter().map(|i| format!("ids={}", i)).collect();
            let path = format!("/ngsiem/entities/rules/v1?{}", ids.join("&"));
            client.get(&path).await
        }
        Action::Search {
            query,
            repository,
            start,
            end,
            timeout,
        } => search(client, &query, &repository, &start, end.as_deref(), timeout).await,
    }
}

/// Start a query job, poll until it completes, and return the final result.
async fn search(
    client: &FalconClient,
    query: &str,
    repository: &str,
    start: &str,
    end: Option<&str>,
    timeout: u64,
) -> Result<serde_json::Value> {
    let mut body = json!({
        "queryString": query,
        "start": start,
        "isLive": false,
    });
    if let Some(end) = end {
        body["end"] = json!(end);
    }

    let jobs_path = format!(
        "/humio/api/v1/repositories/{}/queryjobs",
        encode(repository)
    );
    let job = client.post(&jobs_path, &body).await?;
    let id = job["id"]
        .as_str()
        .ok_or_else(|| FalconError::Api(format!("queryjob id missing in response: {}", job)))?;
    let job_path = format!("{}/{}", jobs_path, encode(id));

    let deadline = Instant::now() + Duration::from_secs(timeout);
    loop {
        let result = client.get(&job_path).await?;
        if result["done"].as_bool().unwrap_or(false) {
            // Free server-side resources; the result is already in hand.
            let _ = client.delete(&job_path).await;
            return Ok(result);
        }
        if Instant::now() >= deadline {
            let _ = client.delete(&job_path).await;
            return Err(FalconError::Api(format!(
                "search did not complete within {}s (job id: {})",
                timeout, id
            )));
        }
        tokio::time::sleep(SEARCH_POLL_INTERVAL).await;
    }
}
