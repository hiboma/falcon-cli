use std::process::Command;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn report_download_preserves_binary_bytes() {
    let server = MockServer::start().await;
    let payload = vec![0x00, 0xff, 0x1f, 0x8b, b'\n', b'\r', 0x80];

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reports/entities/report-executions-download/v1"))
        .and(query_param("ids", "test-report"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(payload.clone()))
        .expect(1)
        .mount(&server)
        .await;

    let base_url = server.uri();
    // Keep blocking process I/O off the runtime serving the mock API, and
    // isolate configuration so no real credential store or agent is consulted.
    let output = tokio::task::spawn_blocking(move || {
        let home = tempfile::tempdir().expect("create home tempdir");
        Command::new(env!("CARGO_BIN_EXE_falcon-cli"))
            .args([
                "--no-agent",
                "--base-url",
                &base_url,
                "report-execution",
                "download",
                "--id",
                "test-report",
            ])
            .current_dir(home.path())
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .env("FALCON_CLIENT_ID", "test-client")
            .env("FALCON_CLIENT_SECRET", "test-secret")
            .env_remove("FALCON_PROFILE")
            .env_remove("FALCON_AGENT_TOKEN")
            .env_remove("FALCON_AGENT_SOCKET")
            .output()
            .expect("run report download")
    })
    .await
    .expect("join CLI process");

    assert!(
        output.status.success(),
        "download failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, payload);
}
