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
fn test_output_format_option() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--output"));
    assert!(stdout.contains("json"));
    assert!(stdout.contains("table"));
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
    let output = Command::new("cargo")
        .args(["run", "--", "host", "list"])
        .env_remove("FALCON_CLIENT_ID")
        .env_remove("FALCON_CLIENT_SECRET")
        .output()
        .expect("failed to execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("FALCON_CLIENT_ID"));
    assert!(!output.status.success());
}
