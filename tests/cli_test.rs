use std::process::Command;

#[test]
fn test_help_output() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("A CLI tool for CrowdStrike Falcon API"));
    assert!(stdout.contains("host"));
    assert!(stdout.contains("detection"));
    assert!(stdout.contains("incident"));
    assert!(stdout.contains("alert"));
}

#[test]
fn test_version_output() {
    let output = Command::new("cargo")
        .args(["run", "--", "--version"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("falcon-cli"));
}

#[test]
fn test_host_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "host", "--help"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("list"));
    assert!(stdout.contains("get"));
}

#[test]
fn test_host_list_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "host", "list", "--help"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--filter"));
    assert!(stdout.contains("--limit"));
    assert!(stdout.contains("--offset"));
}

#[test]
fn test_output_format_hidden_from_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // --output is hidden from help (still functional as a CLI option).
    assert!(!stdout.contains("--output"));
}

#[test]
fn test_all_subcommands_present() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);

    let expected_commands = vec![
        "alert",
        "api-integration",
        "aspm",
        "cao-hunting",
        "case",
        "cert-exclusion",
        "cloud-aws",
        "cloud-azure",
        "cloud-connect-aws",
        "cloud-gcp",
        "cloud-oci",
        "cloud-policy",
        "cloud-security",
        "cloud-asset",
        "cloud-compliance",
        "cloud-detection",
        "cloud-snapshot",
        "config-assessment",
        "config-eval",
        "container-alert",
        "container-detection",
        "container-compliance",
        "container-image",
        "container-package",
        "container-vuln",
        "content-update-policy",
        "correlation-rule",
        "correlation-admin",
        "cspm",
        "custom-ioa",
        "custom-storage",
        "d4c",
        "data-protection",
        "datascanner",
        "delivery-setting",
        "deployment",
        "detection",
        "device-content",
        "device-control-policy",
        "discover",
        "download",
        "drift",
        "event-stream",
        "exposure",
        "faas",
        "falcon-complete",
        "falcon-container",
        "sandbox",
        "fdr",
        "filevantage",
        "firewall",
        "firewall-policy",
        "logscale",
        "host",
        "host-group",
        "host-migration",
        "identity",
        "image-policy",
        "incident",
        "install-token",
        "intel",
        "intel-feed",
        "intel-graph",
        "ioa-exclusion",
        "ioc",
        "iocs",
        "it-automation",
        "k8s-compliance",
        "k8s",
        "malquery",
        "message",
        "ml-exclusion",
        "mobile",
        "mssp",
        "ngsiem",
        "oauth2",
        "ods",
        "overwatch",
        "prevention-policy",
        "quarantine",
        "quick-scan",
        "quick-scan-pro",
        "rtr",
        "rtr-admin",
        "rtr-audit",
        "recon",
        "report-execution",
        "response-policy",
        "saas-security",
        "sample",
        "scheduled-report",
        "sensor-download",
        "sensor-update-policy",
        "sensor-usage",
        "sv-exclusion",
        "serverless-vuln",
        "spotlight-vuln",
        "spotlight-eval",
        "spotlight-metadata",
        "tailored-intel",
        "threatgraph",
        "unidentified-container",
        "user",
        "workflow",
        "zero-trust",
    ];

    for cmd in expected_commands {
        assert!(stdout.contains(cmd), "Missing subcommand: {}", cmd);
    }
}

#[test]
fn test_alert_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "alert", "--help"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("list"));
    assert!(stdout.contains("get"));
    assert!(stdout.contains("update"));
}

#[test]
fn test_alert_update_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "alert", "update", "--help"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--id"));
    assert!(stdout.contains("--status"));
    assert!(stdout.contains("--comment"));
}

#[test]
fn test_missing_credentials_error() {
    // Isolate the subprocess from the developer's real setup: a populated
    // `~/.config/falcon-cli/credentials.toml`, a live agent `session.json`,
    // or a `.falcon-credentials.toml` in the repo root would all let
    // `resolve()` find a secret and defeat the "missing credentials"
    // assertion.
    //
    //   - HOME              -> tempdir so `~/.config/falcon-cli/credentials.toml`
    //                          is unreachable
    //   - XDG_CONFIG_HOME   -> tempdir for the same reason
    //   - current_dir       -> tempdir so `.falcon-credentials.toml` cannot be
    //                          picked up
    //   - FALCON_AGENT_SOCKET cleared alongside FALCON_AGENT_TOKEN
    //
    // We invoke the already-built test binary directly via
    // `CARGO_BIN_EXE_<name>` (auto-populated by cargo for integration tests)
    // rather than `cargo run`, so `current_dir` can be an arbitrary tempdir
    // without cargo complaining about a missing Cargo.toml.
    let home = tempfile::tempdir().expect("create home tempdir");
    let cwd = tempfile::tempdir().expect("create cwd tempdir");
    let bin = env!("CARGO_BIN_EXE_falcon-cli");

    let output = Command::new(bin)
        .args(["--no-agent", "host", "list"])
        .current_dir(cwd.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("FALCON_CLIENT_ID")
        .env_remove("FALCON_CLIENT_SECRET")
        .env_remove("FALCON_AGENT_TOKEN")
        .env_remove("FALCON_AGENT_SOCKET")
        .output()
        .expect("failed to execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FALCON_CLIENT_ID"),
        "expected stderr to mention FALCON_CLIENT_ID, got: {}",
        stderr
    );
    assert!(!output.status.success());
}

#[test]
fn test_doctor_prints_all_sections() {
    // Same isolation as test_missing_credentials_error: a tempdir HOME/XDG/cwd
    // so the developer's real config cannot influence the output.
    let home = tempfile::tempdir().expect("create home tempdir");
    let cwd = tempfile::tempdir().expect("create cwd tempdir");
    let bin = env!("CARGO_BIN_EXE_falcon-cli");

    let output = Command::new(bin)
        .args(["--no-agent", "doctor"])
        .current_dir(cwd.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("FALCON_CLIENT_ID")
        .env_remove("FALCON_CLIENT_SECRET")
        .env_remove("FALCON_BASE_URL")
        .env_remove("FALCON_MEMBER_CID")
        .env_remove("FALCON_PROFILE")
        .env_remove("FALCON_AGENT_TOKEN")
        .env_remove("FALCON_AGENT_SOCKET")
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for section in [
        "CONFIG",
        "RESOLVED CREDENTIALS",
        "ACTIVE PROFILE",
        "ENVIRONMENT",
        "CONNECTIVITY",
    ] {
        assert!(
            stdout.contains(section),
            "doctor output missing section {}: {}",
            section,
            stdout
        );
    }
    // With no credentials, the connectivity probe is skipped, not attempted.
    assert!(
        stdout.contains("SKIPPED"),
        "expected connectivity to be SKIPPED, got: {}",
        stdout
    );
}

#[test]
fn test_doctor_never_leaks_secret_values() {
    // doctor's core guarantee: no secret value reaches stdout/stderr. Feed
    // sentinel values via every source (env, credentials.toml) and assert that
    // none of them appear in the output — only presence and provenance should.
    let home = tempfile::tempdir().expect("create home tempdir");
    let cwd = tempfile::tempdir().expect("create cwd tempdir");
    let bin = env!("CARGO_BIN_EXE_falcon-cli");

    // A credentials.toml under XDG with sentinel secret values.
    let cfg_dir = home.path().join("falcon-cli");
    std::fs::create_dir_all(&cfg_dir).expect("mkdir cfg");
    std::fs::write(
        cfg_dir.join("credentials.toml"),
        "[credentials]\n\
         client_id = \"LEAK_TOML_ID\"\n\
         client_secret = \"LEAK_TOML_SECRET\"\n",
    )
    .expect("write credentials.toml");

    let output = Command::new(bin)
        .args(["--no-agent", "doctor"])
        .current_dir(cwd.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("FALCON_CLIENT_ID", "LEAK_ENV_ID")
        .env("FALCON_CLIENT_SECRET", "LEAK_ENV_SECRET")
        .env("FALCON_AGENT_TOKEN", "LEAK_ENV_TOKEN")
        .env_remove("FALCON_BASE_URL")
        .env_remove("FALCON_MEMBER_CID")
        .env_remove("FALCON_PROFILE")
        .env_remove("FALCON_AGENT_SOCKET")
        .output()
        .expect("failed to execute");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for sentinel in [
        "LEAK_ENV_ID",
        "LEAK_ENV_SECRET",
        "LEAK_ENV_TOKEN",
        "LEAK_TOML_ID",
        "LEAK_TOML_SECRET",
    ] {
        assert!(
            !combined.contains(sentinel),
            "doctor leaked a secret value ({}): {}",
            sentinel,
            combined
        );
    }
    // Sanity: it did resolve them (just without printing the value).
    assert!(combined.contains("RESOLVED CREDENTIALS"));
}

#[test]
fn test_doctor_reports_empty_env_as_set_not_unset() {
    // FalconCredentials::resolve adopts an empty env var (std::env::var(..).ok()
    // returns Some("")), so doctor must not report an empty FALCON_* var as
    // "(unset)" — that would contradict the RESOLVED section. The ENVIRONMENT
    // line for an empty non-sensitive var should read "(set, empty)".
    let home = tempfile::tempdir().expect("create home tempdir");
    let cwd = tempfile::tempdir().expect("create cwd tempdir");
    let bin = env!("CARGO_BIN_EXE_falcon-cli");
    let output = Command::new(bin)
        .args(["--no-agent", "doctor"])
        .current_dir(cwd.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("FALCON_BASE_URL", "") // empty, non-sensitive
        .env_remove("FALCON_CLIENT_ID")
        .env_remove("FALCON_CLIENT_SECRET")
        .env_remove("FALCON_MEMBER_CID")
        .env_remove("FALCON_PROFILE")
        .env_remove("FALCON_AGENT_TOKEN")
        .env_remove("FALCON_AGENT_SOCKET")
        .output()
        .expect("failed to execute");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The ENVIRONMENT section must show FALCON_BASE_URL as set-but-empty,
    // never as (unset).
    let base_url_line = stdout
        .lines()
        .find(|l| l.contains("FALCON_BASE_URL"))
        .unwrap_or_else(|| panic!("no FALCON_BASE_URL line in: {}", stdout));
    assert!(
        base_url_line.contains("(set, empty)"),
        "empty FALCON_BASE_URL should read (set, empty), got: {}",
        base_url_line
    );
    assert!(
        !base_url_line.contains("(unset)"),
        "empty FALCON_BASE_URL must not read (unset), got: {}",
        base_url_line
    );
}
