pub mod alerts;
pub mod api_integrations;
pub mod aspm;
pub mod automated_lead;
pub mod cao_hunting;
pub mod case_management;
pub mod certificate_based_exclusions;
pub mod cloud_aws_registration;
pub mod cloud_azure_registration;
pub mod cloud_connect_aws;
pub mod cloud_google_cloud_registration;
pub mod cloud_oci_registration;
pub mod cloud_policies;
pub mod cloud_security;
pub mod cloud_security_assets;
pub mod cloud_security_compliance;
pub mod cloud_security_detections;
pub mod cloud_snapshots;
pub mod configuration_assessment;
pub mod configuration_assessment_evaluation_logic;
pub mod container_alerts;
pub mod container_detections;
pub mod container_image_compliance;
pub mod container_images;
pub mod container_packages;
pub mod container_vulnerabilities;
pub mod content_update_policies;
pub mod correlation_rules;
pub mod correlation_rules_admin;
pub mod cspm_registration;
pub mod custom_ioa;
pub mod custom_storage;
pub mod d4c_registration;
pub mod data_protection_configuration;
pub mod datascanner;
pub mod delivery_settings;
pub mod deployments;
pub mod detects;
pub mod device_content;
pub mod device_control_policies;
pub mod discover;
pub mod downloads;
pub mod drift_indicators;
pub mod event_streams;
pub mod exposure_management;
pub mod faas_execution;
pub mod falcon_complete_dashboard;
pub mod falcon_container;
pub mod falconx_sandbox;
pub mod fdr;
pub mod filevantage;
pub mod firewall_management;
pub mod firewall_policies;
pub mod foundry_logscale;
pub mod host_group;
pub mod host_migration;
pub mod hosts;
pub mod identity_protection;
pub mod image_assessment_policies;
pub mod incidents;
pub mod installation_tokens;
pub mod intel;
pub mod intelligence_feeds;
pub mod intelligence_indicator_graph;
pub mod ioa_exclusions;
pub mod ioc;
pub mod iocs;
pub mod it_automation;
pub mod kubernetes_container_compliance;
pub mod kubernetes_protection;
pub mod malquery;
pub mod message_center;
pub mod ml_exclusions;
pub mod mobile_enrollment;
pub mod mssp;
pub mod ngsiem;
pub mod oauth2;
pub mod ods;
pub mod overwatch_dashboard;
pub mod prevention_policies;
pub mod quarantine;
pub mod quick_scan;
pub mod quick_scan_pro;
pub mod real_time_response;
pub mod real_time_response_admin;
pub mod real_time_response_audit;
pub mod recon;
pub mod report_executions;
pub mod response_policies;
pub mod saas_security;
pub mod sample_uploads;
pub mod scheduled_reports;
pub mod sensor_download;
pub mod sensor_update_policies;
pub mod sensor_usage;
pub mod sensor_visibility_exclusions;
pub mod serverless_vulnerabilities;
pub mod spotlight_evaluation_logic;
pub mod spotlight_vulnerabilities;
pub mod spotlight_vulnerability_metadata;
pub mod tailored_intelligence;
pub mod threatgraph;
pub mod unidentified_containers;
pub mod user_management;
pub mod workflows;
pub mod zero_trust_assessment;

/// Percent-encode a query parameter value.
fn encode(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                write!(out, "%{:02X}", b).ok();
            }
        }
    }
    out
}

/// Build a query path with optional filter, limit, and offset parameters.
pub fn build_query_path(
    base: &str,
    filter: Option<&str>,
    limit: u32,
    offset: Option<&str>,
) -> String {
    let mut path = format!("{}?limit={}", base, limit);
    if let Some(f) = filter {
        path.push_str(&format!("&filter={}", encode(f)));
    }
    if let Some(o) = offset {
        path.push_str(&format!("&offset={}", encode(o)));
    }
    path
}

/// Build a query string for multiple IDs.
#[allow(dead_code)]
pub fn build_ids_query(base: &str, ids: &[String]) -> String {
    let params: Vec<String> = ids.iter().map(|i| format!("ids={}", encode(i))).collect();
    format!("{}?{}", base, params.join("&"))
}
