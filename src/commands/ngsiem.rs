use std::time::{Duration, Instant};

use clap::Subcommand;
use serde_json::json;

use crate::client::FalconClient;
use crate::commands::{build_query_path, encode};
use crate::error::{FalconError, Result};

const SEARCH_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// The poll interval doubles after every poll up to this cap, so long
/// `--timeout` values do not hammer the API.
const SEARCH_POLL_MAX_INTERVAL: Duration = Duration::from_secs(5);

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

/// Reject repository names that would escape the intended URL path.
/// `.` and `..` survive percent-encoding as-is and are collapsed as
/// dot segments when the URL is parsed.
fn validate_repository(repository: &str) -> Result<()> {
    if repository.is_empty() || repository == "." || repository == ".." {
        return Err(FalconError::InvalidInput(format!(
            "invalid repository name: {:?}",
            repository
        )));
    }
    Ok(())
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
    validate_repository(repository)?;

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
    let id = job["id"].as_str().ok_or_else(|| {
        FalconError::Api(format!(
            "queryjob id missing in response: {}",
            FalconClient::truncate_chars(&job.to_string(), 200)
        ))
    })?;
    let job_path = format!("{}/{}", jobs_path, encode(id));

    let outcome = tokio::select! {
        res = poll_until_done(client, &job_path, id, timeout) => res,
        // Ctrl-C: fall through to the cleanup below instead of leaving
        // the query job running server-side.
        _ = tokio::signal::ctrl_c() => Err(FalconError::Api(format!(
            "search interrupted (job id: {})",
            id
        ))),
    };

    // Free server-side resources in every outcome; on success the result
    // is already in hand. A failed cleanup is not worth surfacing.
    let _ = client.delete(&job_path).await;

    outcome
}

/// Poll a query job until `done: true`, a poll fails, or `timeout` elapses.
async fn poll_until_done(
    client: &FalconClient,
    job_path: &str,
    id: &str,
    timeout: u64,
) -> Result<serde_json::Value> {
    let started = Instant::now();
    let limit = Duration::from_secs(timeout);
    let mut interval = SEARCH_POLL_INTERVAL;
    loop {
        let result = client.get(job_path).await?;
        if result["done"].as_bool().unwrap_or(false) {
            return Ok(result);
        }
        if started.elapsed() >= limit {
            return Err(FalconError::Api(format!(
                "search did not complete within {}s (job id: {})",
                timeout, id
            )));
        }
        tokio::time::sleep(interval).await;
        interval = (interval * 2).min(SEARCH_POLL_MAX_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_repository_accepts_normal_names() {
        assert!(validate_repository("search-all").is_ok());
        assert!(validate_repository("my.repo").is_ok());
    }

    #[test]
    fn test_validate_repository_rejects_dot_segments() {
        assert!(validate_repository("").is_err());
        assert!(validate_repository(".").is_err());
        assert!(validate_repository("..").is_err());
    }

    mod search_lifecycle {
        use super::super::search;
        use crate::client::test_support::mock_client;
        use serde_json::json;
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const JOBS_PATH: &str = "/humio/api/v1/repositories/search-all/queryjobs";
        const JOB_PATH: &str = "/humio/api/v1/repositories/search-all/queryjobs/job-1";

        async fn mount_job_created(server: &MockServer) {
            Mock::given(method("POST"))
                .and(path(JOBS_PATH))
                .and(body_partial_json(json!({"isLive": false})))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "job-1"})))
                .expect(1)
                .mount(server)
                .await;
        }

        async fn mount_job_deleted(server: &MockServer) {
            Mock::given(method("DELETE"))
                .and(path(JOB_PATH))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(server)
                .await;
        }

        #[tokio::test]
        async fn polls_until_done_and_deletes_the_job() {
            let server = MockServer::start().await;
            let client = mock_client(&server).await;
            mount_job_created(&server).await;
            mount_job_deleted(&server).await;

            // The first poll is still running; it is mounted first and
            // limited to one match so the retry falls through to "done".
            Mock::given(method("GET"))
                .and(path(JOB_PATH))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"done": false})))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(JOB_PATH))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "done": true,
                    "events": [{"#event_simpleName": "ProcessRollup2"}],
                })))
                .mount(&server)
                .await;

            let result = search(
                &client,
                "#event_simpleName=Foo",
                "search-all",
                "1h",
                None,
                60,
            )
            .await
            .expect("search completes");
            assert_eq!(result["done"], json!(true));
            assert_eq!(result["events"].as_array().map(Vec::len), Some(1));
        }

        #[tokio::test]
        async fn deletes_the_job_when_a_poll_fails() {
            let server = MockServer::start().await;
            let client = mock_client(&server).await;
            mount_job_created(&server).await;
            mount_job_deleted(&server).await;

            Mock::given(method("GET"))
                .and(path(JOB_PATH))
                .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
                .expect(1)
                .mount(&server)
                .await;

            let err = search(&client, "q", "search-all", "1h", None, 60)
                .await
                .expect_err("poll failure propagates");
            assert!(err.to_string().contains("500"));
        }

        #[tokio::test]
        async fn deletes_the_job_on_timeout() {
            let server = MockServer::start().await;
            let client = mock_client(&server).await;
            mount_job_created(&server).await;
            mount_job_deleted(&server).await;

            // --timeout 0: a single not-done poll trips the deadline
            // without sleeping, keeping the test fast.
            Mock::given(method("GET"))
                .and(path(JOB_PATH))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"done": false})))
                .expect(1)
                .mount(&server)
                .await;

            let err = search(&client, "q", "search-all", "1h", None, 0)
                .await
                .expect_err("timeout is an error");
            let msg = err.to_string();
            assert!(msg.contains("did not complete within 0s"));
            assert!(msg.contains("job-1"));
        }

        #[tokio::test]
        async fn reports_a_missing_job_id() {
            let server = MockServer::start().await;
            let client = mock_client(&server).await;

            Mock::given(method("POST"))
                .and(path(JOBS_PATH))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .expect(1)
                .mount(&server)
                .await;

            let err = search(&client, "q", "search-all", "1h", None, 60)
                .await
                .expect_err("missing id is an error");
            assert!(err.to_string().contains("queryjob id missing"));
        }

        #[tokio::test]
        async fn passes_the_end_bound_through() {
            let server = MockServer::start().await;
            let client = mock_client(&server).await;
            mount_job_deleted(&server).await;

            Mock::given(method("POST"))
                .and(path(JOBS_PATH))
                .and(body_partial_json(json!({
                    "queryString": "q",
                    "start": "2h",
                    "end": "1h",
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "job-1"})))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(JOB_PATH))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"done": true})))
                .mount(&server)
                .await;

            search(&client, "q", "search-all", "2h", Some("1h"), 60)
                .await
                .expect("search completes");
        }
    }
}
