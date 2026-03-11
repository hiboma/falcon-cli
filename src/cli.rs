use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::commands;

const HELP_TEMPLATE: &str = "\
{about-with-newline}
{usage-heading} {usage}

Options:
{options}
Commands:

Detection & Response:
  alert, detection, incident, rtr, rtr-admin, rtr-audit,
  recon, overwatch, sandbox, quarantine, drift

Host Management:
  host, host-group, host-migration, discover,
  device-content, device-control-policy

Policy Management:
  prevention-policy, response-policy, sensor-update-policy,
  content-update-policy, firewall-policy

Cloud Security:
  cloud-aws, cloud-azure, cloud-connect-aws, cloud-gcp, cloud-oci,
  cloud-policy, cloud-security, cloud-asset, cloud-compliance,
  cloud-detection, cloud-snapshot, cspm, d4c

Container & Kubernetes:
  container-alert, container-detection, container-compliance,
  container-image, container-package, container-vuln,
  falcon-container, k8s, k8s-compliance,
  unidentified-container, image-policy

Vulnerability Management:
  spotlight-vuln, spotlight-eval, spotlight-metadata,
  serverless-vuln, exposure, config-assessment, config-eval

Exclusions & IOC:
  ioa-exclusion, ioc, iocs, ml-exclusion, sv-exclusion,
  cert-exclusion, custom-ioa

Threat Intelligence:
  intel, intel-feed, intel-graph, tailored-intel,
  threatgraph, malquery

Sensor & Downloads:
  sensor-download, sensor-usage, install-token,
  download, deployment

Scanning & Compliance:
  quick-scan, quick-scan-pro, ods, filevantage,
  datascanner, data-protection

Identity & Access:
  identity, user, oauth2, zero-trust, mobile, mssp

Monitoring & Reporting:
  event-stream, message, report-execution, scheduled-report,
  case, falcon-complete, workflow, it-automation

Platform & Integration:
  api-integration, aspm, cao-hunting, correlation-rule,
  correlation-admin, custom-storage, delivery-setting, fdr,
  firewall, logscale, ngsiem, sample, saas-security, faas
";

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Json,
    Table,
}

#[derive(Parser, Debug)]
#[command(
    name = "falcon-cli",
    about = "A CLI tool for CrowdStrike Falcon API",
    version,
    propagate_version = true,
    disable_help_subcommand = true,
    help_template = HELP_TEMPLATE
)]
pub struct Cli {
    /// CrowdStrike API client ID (overrides FALCON_CLIENT_ID)
    #[arg(long, env = "FALCON_CLIENT_ID", hide_env = true)]
    pub client_id: Option<String>,

    /// Base URL for the Falcon API (overrides FALCON_BASE_URL)
    #[arg(long, env = "FALCON_BASE_URL", hide_env = true)]
    pub base_url: Option<String>,

    /// Member CID for MSSP (overrides FALCON_MEMBER_CID)
    #[arg(long, env = "FALCON_MEMBER_CID", hide_env = true)]
    pub member_cid: Option<String>,

    /// Output format (json or table)
    #[arg(long, short, default_value = "json")]
    pub output: OutputFormat,

    /// Pretty-print JSON output
    #[arg(long)]
    pub pretty: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    // ── Detection & Response ──
    /// Manage alerts
    #[command(next_help_heading = "Detection & Response")]
    Alert {
        #[command(subcommand)]
        action: commands::alerts::Action,
    },
    /// Manage detections
    #[command(next_help_heading = "Detection & Response")]
    Detection {
        #[command(subcommand)]
        action: commands::detects::Action,
    },
    /// Manage incidents
    #[command(next_help_heading = "Detection & Response")]
    Incident {
        #[command(subcommand)]
        action: commands::incidents::Action,
    },
    /// Manage real-time response sessions
    #[command(next_help_heading = "Detection & Response")]
    Rtr {
        #[command(subcommand)]
        action: commands::real_time_response::Action,
    },
    /// Manage real-time response (admin)
    #[command(next_help_heading = "Detection & Response")]
    RtrAdmin {
        #[command(subcommand)]
        action: commands::real_time_response_admin::Action,
    },
    /// Manage real-time response audit
    #[command(next_help_heading = "Detection & Response")]
    RtrAudit {
        #[command(subcommand)]
        action: commands::real_time_response_audit::Action,
    },
    /// Manage recon monitoring rules
    #[command(next_help_heading = "Detection & Response")]
    Recon {
        #[command(subcommand)]
        action: commands::recon::Action,
    },
    /// Manage OverWatch dashboard
    #[command(next_help_heading = "Detection & Response")]
    Overwatch {
        #[command(subcommand)]
        action: commands::overwatch_dashboard::Action,
    },
    /// Manage Falcon Intelligence Sandbox
    #[command(next_help_heading = "Detection & Response")]
    Sandbox {
        #[command(subcommand)]
        action: commands::falconx_sandbox::Action,
    },
    /// Manage quarantined files
    #[command(next_help_heading = "Detection & Response")]
    Quarantine {
        #[command(subcommand)]
        action: commands::quarantine::Action,
    },
    /// Manage drift indicators
    #[command(next_help_heading = "Detection & Response")]
    Drift {
        #[command(subcommand)]
        action: commands::drift_indicators::Action,
    },

    // ── Host Management ──
    /// Manage hosts
    #[command(next_help_heading = "Host Management")]
    Host {
        #[command(subcommand)]
        action: commands::hosts::Action,
    },
    /// Manage host groups
    #[command(next_help_heading = "Host Management")]
    HostGroup {
        #[command(subcommand)]
        action: commands::host_group::Action,
    },
    /// Manage host migrations
    #[command(next_help_heading = "Host Management")]
    HostMigration {
        #[command(subcommand)]
        action: commands::host_migration::Action,
    },
    /// Discover assets
    #[command(next_help_heading = "Host Management")]
    Discover {
        #[command(subcommand)]
        action: commands::discover::Action,
    },
    /// Manage device content
    #[command(next_help_heading = "Host Management")]
    DeviceContent {
        #[command(subcommand)]
        action: commands::device_content::Action,
    },
    /// Manage device control policies
    #[command(next_help_heading = "Host Management")]
    DeviceControlPolicy {
        #[command(subcommand)]
        action: commands::device_control_policies::Action,
    },

    // ── Policy Management ──
    /// Manage prevention policies
    #[command(next_help_heading = "Policy Management")]
    PreventionPolicy {
        #[command(subcommand)]
        action: commands::prevention_policies::Action,
    },
    /// Manage response policies
    #[command(next_help_heading = "Policy Management")]
    ResponsePolicy {
        #[command(subcommand)]
        action: commands::response_policies::Action,
    },
    /// Manage sensor update policies
    #[command(next_help_heading = "Policy Management")]
    SensorUpdatePolicy {
        #[command(subcommand)]
        action: commands::sensor_update_policies::Action,
    },
    /// Manage content update policies
    #[command(next_help_heading = "Policy Management")]
    ContentUpdatePolicy {
        #[command(subcommand)]
        action: commands::content_update_policies::Action,
    },
    /// Manage firewall policies
    #[command(next_help_heading = "Policy Management")]
    FirewallPolicy {
        #[command(subcommand)]
        action: commands::firewall_policies::Action,
    },

    // ── Cloud Security ──
    /// Manage AWS cloud registration
    #[command(next_help_heading = "Cloud Security")]
    CloudAws {
        #[command(subcommand)]
        action: commands::cloud_aws_registration::Action,
    },
    /// Manage Azure cloud registration
    #[command(next_help_heading = "Cloud Security")]
    CloudAzure {
        #[command(subcommand)]
        action: commands::cloud_azure_registration::Action,
    },
    /// Manage AWS cloud connections
    #[command(next_help_heading = "Cloud Security")]
    CloudConnectAws {
        #[command(subcommand)]
        action: commands::cloud_connect_aws::Action,
    },
    /// Manage GCP cloud registration
    #[command(next_help_heading = "Cloud Security")]
    CloudGcp {
        #[command(subcommand)]
        action: commands::cloud_google_cloud_registration::Action,
    },
    /// Manage OCI cloud registration
    #[command(next_help_heading = "Cloud Security")]
    CloudOci {
        #[command(subcommand)]
        action: commands::cloud_oci_registration::Action,
    },
    /// Manage cloud policies
    #[command(next_help_heading = "Cloud Security")]
    CloudPolicy {
        #[command(subcommand)]
        action: commands::cloud_policies::Action,
    },
    /// Manage cloud security
    #[command(next_help_heading = "Cloud Security")]
    CloudSecurity {
        #[command(subcommand)]
        action: commands::cloud_security::Action,
    },
    /// Manage cloud security assets
    #[command(next_help_heading = "Cloud Security")]
    CloudAsset {
        #[command(subcommand)]
        action: commands::cloud_security_assets::Action,
    },
    /// Manage cloud security compliance
    #[command(next_help_heading = "Cloud Security")]
    CloudCompliance {
        #[command(subcommand)]
        action: commands::cloud_security_compliance::Action,
    },
    /// Manage cloud security detections
    #[command(next_help_heading = "Cloud Security")]
    CloudDetection {
        #[command(subcommand)]
        action: commands::cloud_security_detections::Action,
    },
    /// Manage cloud snapshots
    #[command(next_help_heading = "Cloud Security")]
    CloudSnapshot {
        #[command(subcommand)]
        action: commands::cloud_snapshots::Action,
    },
    /// Manage CSPM registration
    #[command(next_help_heading = "Cloud Security")]
    Cspm {
        #[command(subcommand)]
        action: commands::cspm_registration::Action,
    },
    /// Manage D4C registration
    #[command(next_help_heading = "Cloud Security")]
    D4c {
        #[command(subcommand)]
        action: commands::d4c_registration::Action,
    },

    // ── Container & Kubernetes ──
    /// Manage container alerts
    #[command(next_help_heading = "Container & Kubernetes")]
    ContainerAlert {
        #[command(subcommand)]
        action: commands::container_alerts::Action,
    },
    /// Manage container detections
    #[command(next_help_heading = "Container & Kubernetes")]
    ContainerDetection {
        #[command(subcommand)]
        action: commands::container_detections::Action,
    },
    /// Manage container image compliance
    #[command(next_help_heading = "Container & Kubernetes")]
    ContainerCompliance {
        #[command(subcommand)]
        action: commands::container_image_compliance::Action,
    },
    /// Manage container images
    #[command(next_help_heading = "Container & Kubernetes")]
    ContainerImage {
        #[command(subcommand)]
        action: commands::container_images::Action,
    },
    /// Manage container packages
    #[command(next_help_heading = "Container & Kubernetes")]
    ContainerPackage {
        #[command(subcommand)]
        action: commands::container_packages::Action,
    },
    /// Manage container vulnerabilities
    #[command(next_help_heading = "Container & Kubernetes")]
    ContainerVuln {
        #[command(subcommand)]
        action: commands::container_vulnerabilities::Action,
    },
    /// Manage Falcon container
    #[command(next_help_heading = "Container & Kubernetes")]
    FalconContainer {
        #[command(subcommand)]
        action: commands::falcon_container::Action,
    },
    /// Manage Kubernetes protection
    #[command(next_help_heading = "Container & Kubernetes")]
    K8s {
        #[command(subcommand)]
        action: commands::kubernetes_protection::Action,
    },
    /// Manage Kubernetes container compliance
    #[command(next_help_heading = "Container & Kubernetes")]
    K8sCompliance {
        #[command(subcommand)]
        action: commands::kubernetes_container_compliance::Action,
    },
    /// Manage unidentified containers
    #[command(next_help_heading = "Container & Kubernetes")]
    UnidentifiedContainer {
        #[command(subcommand)]
        action: commands::unidentified_containers::Action,
    },
    /// Manage image assessment policies
    #[command(next_help_heading = "Container & Kubernetes")]
    ImagePolicy {
        #[command(subcommand)]
        action: commands::image_assessment_policies::Action,
    },

    // ── Vulnerability Management ──
    /// Manage Spotlight vulnerabilities
    #[command(next_help_heading = "Vulnerability Management")]
    SpotlightVuln {
        #[command(subcommand)]
        action: commands::spotlight_vulnerabilities::Action,
    },
    /// Manage Spotlight evaluation logic
    #[command(next_help_heading = "Vulnerability Management")]
    SpotlightEval {
        #[command(subcommand)]
        action: commands::spotlight_evaluation_logic::Action,
    },
    /// Manage Spotlight vulnerability metadata
    #[command(next_help_heading = "Vulnerability Management")]
    SpotlightMetadata {
        #[command(subcommand)]
        action: commands::spotlight_vulnerability_metadata::Action,
    },
    /// Manage serverless vulnerabilities
    #[command(next_help_heading = "Vulnerability Management")]
    ServerlessVuln {
        #[command(subcommand)]
        action: commands::serverless_vulnerabilities::Action,
    },
    /// Manage exposure
    #[command(next_help_heading = "Vulnerability Management")]
    Exposure {
        #[command(subcommand)]
        action: commands::exposure_management::Action,
    },
    /// Manage configuration assessments
    #[command(next_help_heading = "Vulnerability Management")]
    ConfigAssessment {
        #[command(subcommand)]
        action: commands::configuration_assessment::Action,
    },
    /// Manage configuration assessment evaluation logic
    #[command(next_help_heading = "Vulnerability Management")]
    ConfigEval {
        #[command(subcommand)]
        action: commands::configuration_assessment_evaluation_logic::Action,
    },

    // ── Exclusions & IOC ──
    /// Manage IOA exclusions
    #[command(next_help_heading = "Exclusions & IOC")]
    IoaExclusion {
        #[command(subcommand)]
        action: commands::ioa_exclusions::Action,
    },
    /// Manage IOC indicators
    #[command(next_help_heading = "Exclusions & IOC")]
    Ioc {
        #[command(subcommand)]
        action: commands::ioc::Action,
    },
    /// Manage IOCs (legacy)
    #[command(next_help_heading = "Exclusions & IOC")]
    Iocs {
        #[command(subcommand)]
        action: commands::iocs::Action,
    },
    /// Manage ML exclusions
    #[command(next_help_heading = "Exclusions & IOC")]
    MlExclusion {
        #[command(subcommand)]
        action: commands::ml_exclusions::Action,
    },
    /// Manage sensor visibility exclusions
    #[command(next_help_heading = "Exclusions & IOC")]
    SvExclusion {
        #[command(subcommand)]
        action: commands::sensor_visibility_exclusions::Action,
    },
    /// Manage certificate-based exclusions
    #[command(next_help_heading = "Exclusions & IOC")]
    CertExclusion {
        #[command(subcommand)]
        action: commands::certificate_based_exclusions::Action,
    },
    /// Manage custom IOA rules
    #[command(next_help_heading = "Exclusions & IOC")]
    CustomIoa {
        #[command(subcommand)]
        action: commands::custom_ioa::Action,
    },

    // ── Threat Intelligence ──
    /// Manage threat intelligence
    #[command(next_help_heading = "Threat Intelligence")]
    Intel {
        #[command(subcommand)]
        action: commands::intel::Action,
    },
    /// Manage intelligence feeds
    #[command(next_help_heading = "Threat Intelligence")]
    IntelFeed {
        #[command(subcommand)]
        action: commands::intelligence_feeds::Action,
    },
    /// Manage intelligence indicator graph
    #[command(next_help_heading = "Threat Intelligence")]
    IntelGraph {
        #[command(subcommand)]
        action: commands::intelligence_indicator_graph::Action,
    },
    /// Manage tailored intelligence
    #[command(next_help_heading = "Threat Intelligence")]
    TailoredIntel {
        #[command(subcommand)]
        action: commands::tailored_intelligence::Action,
    },
    /// Manage ThreatGraph
    #[command(next_help_heading = "Threat Intelligence")]
    Threatgraph {
        #[command(subcommand)]
        action: commands::threatgraph::Action,
    },
    /// Manage MalQuery
    #[command(next_help_heading = "Threat Intelligence")]
    Malquery {
        #[command(subcommand)]
        action: commands::malquery::Action,
    },

    // ── Sensor & Downloads ──
    /// Manage sensor downloads
    #[command(next_help_heading = "Sensor & Downloads")]
    SensorDownload {
        #[command(subcommand)]
        action: commands::sensor_download::Action,
    },
    /// Manage sensor usage
    #[command(next_help_heading = "Sensor & Downloads")]
    SensorUsage {
        #[command(subcommand)]
        action: commands::sensor_usage::Action,
    },
    /// Manage installation tokens
    #[command(next_help_heading = "Sensor & Downloads")]
    InstallToken {
        #[command(subcommand)]
        action: commands::installation_tokens::Action,
    },
    /// Manage downloads
    #[command(next_help_heading = "Sensor & Downloads")]
    Download {
        #[command(subcommand)]
        action: commands::downloads::Action,
    },
    /// Manage deployments
    #[command(next_help_heading = "Sensor & Downloads")]
    Deployment {
        #[command(subcommand)]
        action: commands::deployments::Action,
    },

    // ── Scanning & Compliance ──
    /// Manage quick scans
    #[command(next_help_heading = "Scanning & Compliance")]
    QuickScan {
        #[command(subcommand)]
        action: commands::quick_scan::Action,
    },
    /// Manage quick scans (pro)
    #[command(next_help_heading = "Scanning & Compliance")]
    QuickScanPro {
        #[command(subcommand)]
        action: commands::quick_scan_pro::Action,
    },
    /// Manage on-demand scans
    #[command(next_help_heading = "Scanning & Compliance")]
    Ods {
        #[command(subcommand)]
        action: commands::ods::Action,
    },
    /// Manage FileVantage
    #[command(next_help_heading = "Scanning & Compliance")]
    Filevantage {
        #[command(subcommand)]
        action: commands::filevantage::Action,
    },
    /// Manage DataScanner
    #[command(next_help_heading = "Scanning & Compliance")]
    Datascanner {
        #[command(subcommand)]
        action: commands::datascanner::Action,
    },
    /// Manage data protection configuration
    #[command(next_help_heading = "Scanning & Compliance")]
    DataProtection {
        #[command(subcommand)]
        action: commands::data_protection_configuration::Action,
    },

    // ── Identity & Access ──
    /// Manage identity protection
    #[command(next_help_heading = "Identity & Access")]
    Identity {
        #[command(subcommand)]
        action: commands::identity_protection::Action,
    },
    /// Manage users
    #[command(next_help_heading = "Identity & Access")]
    User {
        #[command(subcommand)]
        action: commands::user_management::Action,
    },
    /// Manage OAuth2 tokens
    #[command(next_help_heading = "Identity & Access")]
    Oauth2 {
        #[command(subcommand)]
        action: commands::oauth2::Action,
    },
    /// Manage Zero Trust assessments
    #[command(next_help_heading = "Identity & Access")]
    ZeroTrust {
        #[command(subcommand)]
        action: commands::zero_trust_assessment::Action,
    },
    /// Manage mobile enrollment
    #[command(next_help_heading = "Identity & Access")]
    Mobile {
        #[command(subcommand)]
        action: commands::mobile_enrollment::Action,
    },
    /// Manage MSSP (Flight Control)
    #[command(next_help_heading = "Identity & Access")]
    Mssp {
        #[command(subcommand)]
        action: commands::mssp::Action,
    },

    // ── Monitoring & Reporting ──
    /// Manage event streams
    #[command(next_help_heading = "Monitoring & Reporting")]
    EventStream {
        #[command(subcommand)]
        action: commands::event_streams::Action,
    },
    /// Manage message center
    #[command(next_help_heading = "Monitoring & Reporting")]
    Message {
        #[command(subcommand)]
        action: commands::message_center::Action,
    },
    /// Manage report executions
    #[command(next_help_heading = "Monitoring & Reporting")]
    ReportExecution {
        #[command(subcommand)]
        action: commands::report_executions::Action,
    },
    /// Manage scheduled reports
    #[command(next_help_heading = "Monitoring & Reporting")]
    ScheduledReport {
        #[command(subcommand)]
        action: commands::scheduled_reports::Action,
    },
    /// Manage cases
    #[command(next_help_heading = "Monitoring & Reporting")]
    Case {
        #[command(subcommand)]
        action: commands::case_management::Action,
    },
    /// Manage Falcon Complete dashboard
    #[command(next_help_heading = "Monitoring & Reporting")]
    FalconComplete {
        #[command(subcommand)]
        action: commands::falcon_complete_dashboard::Action,
    },
    /// Manage workflows
    #[command(next_help_heading = "Monitoring & Reporting")]
    Workflow {
        #[command(subcommand)]
        action: commands::workflows::Action,
    },
    /// Manage IT automation
    #[command(next_help_heading = "Monitoring & Reporting")]
    ItAutomation {
        #[command(subcommand)]
        action: commands::it_automation::Action,
    },

    // ── Platform & Integration ──
    /// Manage API integrations
    #[command(next_help_heading = "Platform & Integration")]
    ApiIntegration {
        #[command(subcommand)]
        action: commands::api_integrations::Action,
    },
    /// Manage ASPM
    #[command(next_help_heading = "Platform & Integration")]
    Aspm {
        #[command(subcommand)]
        action: commands::aspm::Action,
    },
    /// Manage CAO hunting
    #[command(next_help_heading = "Platform & Integration")]
    CaoHunting {
        #[command(subcommand)]
        action: commands::cao_hunting::Action,
    },
    /// Manage correlation rules
    #[command(next_help_heading = "Platform & Integration")]
    CorrelationRule {
        #[command(subcommand)]
        action: commands::correlation_rules::Action,
    },
    /// Manage correlation rules (admin)
    #[command(next_help_heading = "Platform & Integration")]
    CorrelationAdmin {
        #[command(subcommand)]
        action: commands::correlation_rules_admin::Action,
    },
    /// Manage custom storage
    #[command(next_help_heading = "Platform & Integration")]
    CustomStorage {
        #[command(subcommand)]
        action: commands::custom_storage::Action,
    },
    /// Manage delivery settings
    #[command(next_help_heading = "Platform & Integration")]
    DeliverySetting {
        #[command(subcommand)]
        action: commands::delivery_settings::Action,
    },
    /// Manage FDR
    #[command(next_help_heading = "Platform & Integration")]
    Fdr {
        #[command(subcommand)]
        action: commands::fdr::Action,
    },
    /// Manage firewall rules
    #[command(next_help_heading = "Platform & Integration")]
    Firewall {
        #[command(subcommand)]
        action: commands::firewall_management::Action,
    },
    /// Manage Foundry LogScale
    #[command(next_help_heading = "Platform & Integration")]
    Logscale {
        #[command(subcommand)]
        action: commands::foundry_logscale::Action,
    },
    /// Manage NGSIEM
    #[command(next_help_heading = "Platform & Integration")]
    Ngsiem {
        #[command(subcommand)]
        action: commands::ngsiem::Action,
    },
    /// Manage sample uploads
    #[command(next_help_heading = "Platform & Integration")]
    Sample {
        #[command(subcommand)]
        action: commands::sample_uploads::Action,
    },
    /// Manage SaaS security
    #[command(next_help_heading = "Platform & Integration")]
    SaasSecurity {
        #[command(subcommand)]
        action: commands::saas_security::Action,
    },
    /// Manage FaaS executions
    #[command(next_help_heading = "Platform & Integration")]
    Faas {
        #[command(subcommand)]
        action: commands::faas_execution::Action,
    },
    /// Generate shell completion scripts
    Completion {
        /// Target shell
        shell: Shell,
    },
    // ── Extended (multi-API) ──
    // Commands below combine multiple Falcon API calls into a single operation.
    // They are falcon-cli specific and do not map 1:1 to a Falcon API endpoint.
    /// Investigate automated-lead alerts [multi-API]
    AutomatedLead {
        #[command(subcommand)]
        action: commands::automated_lead::Action,
    },
}
