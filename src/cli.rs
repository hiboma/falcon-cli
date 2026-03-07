use clap::{Parser, Subcommand, ValueEnum};

use crate::commands;

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
    propagate_version = true
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

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Manage alerts (list, get, automated-lead)
    Alert {
        #[command(subcommand)]
        action: commands::alerts::Action,
    },
    /// Manage API integrations
    ApiIntegration {
        #[command(subcommand)]
        action: commands::api_integrations::Action,
    },
    /// Manage ASPM
    Aspm {
        #[command(subcommand)]
        action: commands::aspm::Action,
    },
    /// Manage CAO hunting
    CaoHunting {
        #[command(subcommand)]
        action: commands::cao_hunting::Action,
    },
    /// Manage cases
    Case {
        #[command(subcommand)]
        action: commands::case_management::Action,
    },
    /// Manage certificate-based exclusions
    CertExclusion {
        #[command(subcommand)]
        action: commands::certificate_based_exclusions::Action,
    },
    /// Manage AWS cloud registration
    CloudAws {
        #[command(subcommand)]
        action: commands::cloud_aws_registration::Action,
    },
    /// Manage Azure cloud registration
    CloudAzure {
        #[command(subcommand)]
        action: commands::cloud_azure_registration::Action,
    },
    /// Manage AWS cloud connections
    CloudConnectAws {
        #[command(subcommand)]
        action: commands::cloud_connect_aws::Action,
    },
    /// Manage GCP cloud registration
    CloudGcp {
        #[command(subcommand)]
        action: commands::cloud_google_cloud_registration::Action,
    },
    /// Manage OCI cloud registration
    CloudOci {
        #[command(subcommand)]
        action: commands::cloud_oci_registration::Action,
    },
    /// Manage cloud policies
    CloudPolicy {
        #[command(subcommand)]
        action: commands::cloud_policies::Action,
    },
    /// Manage cloud security
    CloudSecurity {
        #[command(subcommand)]
        action: commands::cloud_security::Action,
    },
    /// Manage cloud security assets
    CloudAsset {
        #[command(subcommand)]
        action: commands::cloud_security_assets::Action,
    },
    /// Manage cloud security compliance
    CloudCompliance {
        #[command(subcommand)]
        action: commands::cloud_security_compliance::Action,
    },
    /// Manage cloud security detections
    CloudDetection {
        #[command(subcommand)]
        action: commands::cloud_security_detections::Action,
    },
    /// Manage cloud snapshots
    CloudSnapshot {
        #[command(subcommand)]
        action: commands::cloud_snapshots::Action,
    },
    /// Manage configuration assessments
    ConfigAssessment {
        #[command(subcommand)]
        action: commands::configuration_assessment::Action,
    },
    /// Manage configuration assessment evaluation logic
    ConfigEval {
        #[command(subcommand)]
        action: commands::configuration_assessment_evaluation_logic::Action,
    },
    /// Manage container alerts
    ContainerAlert {
        #[command(subcommand)]
        action: commands::container_alerts::Action,
    },
    /// Manage container detections
    ContainerDetection {
        #[command(subcommand)]
        action: commands::container_detections::Action,
    },
    /// Manage container image compliance
    ContainerCompliance {
        #[command(subcommand)]
        action: commands::container_image_compliance::Action,
    },
    /// Manage container images
    ContainerImage {
        #[command(subcommand)]
        action: commands::container_images::Action,
    },
    /// Manage container packages
    ContainerPackage {
        #[command(subcommand)]
        action: commands::container_packages::Action,
    },
    /// Manage container vulnerabilities
    ContainerVuln {
        #[command(subcommand)]
        action: commands::container_vulnerabilities::Action,
    },
    /// Manage content update policies
    ContentUpdatePolicy {
        #[command(subcommand)]
        action: commands::content_update_policies::Action,
    },
    /// Manage correlation rules
    CorrelationRule {
        #[command(subcommand)]
        action: commands::correlation_rules::Action,
    },
    /// Manage correlation rules (admin)
    CorrelationAdmin {
        #[command(subcommand)]
        action: commands::correlation_rules_admin::Action,
    },
    /// Manage CSPM registration
    Cspm {
        #[command(subcommand)]
        action: commands::cspm_registration::Action,
    },
    /// Manage custom IOA rules
    CustomIoa {
        #[command(subcommand)]
        action: commands::custom_ioa::Action,
    },
    /// Manage custom storage
    CustomStorage {
        #[command(subcommand)]
        action: commands::custom_storage::Action,
    },
    /// Manage D4C registration
    D4c {
        #[command(subcommand)]
        action: commands::d4c_registration::Action,
    },
    /// Manage data protection configuration
    DataProtection {
        #[command(subcommand)]
        action: commands::data_protection_configuration::Action,
    },
    /// Manage DataScanner
    Datascanner {
        #[command(subcommand)]
        action: commands::datascanner::Action,
    },
    /// Manage delivery settings
    DeliverySetting {
        #[command(subcommand)]
        action: commands::delivery_settings::Action,
    },
    /// Manage deployments
    Deployment {
        #[command(subcommand)]
        action: commands::deployments::Action,
    },
    /// Manage detections
    Detection {
        #[command(subcommand)]
        action: commands::detects::Action,
    },
    /// Manage device content
    DeviceContent {
        #[command(subcommand)]
        action: commands::device_content::Action,
    },
    /// Manage device control policies
    DeviceControlPolicy {
        #[command(subcommand)]
        action: commands::device_control_policies::Action,
    },
    /// Discover assets
    Discover {
        #[command(subcommand)]
        action: commands::discover::Action,
    },
    /// Manage downloads
    Download {
        #[command(subcommand)]
        action: commands::downloads::Action,
    },
    /// Manage drift indicators
    Drift {
        #[command(subcommand)]
        action: commands::drift_indicators::Action,
    },
    /// Manage event streams
    EventStream {
        #[command(subcommand)]
        action: commands::event_streams::Action,
    },
    /// Manage exposure
    Exposure {
        #[command(subcommand)]
        action: commands::exposure_management::Action,
    },
    /// Manage FaaS executions
    Faas {
        #[command(subcommand)]
        action: commands::faas_execution::Action,
    },
    /// Manage Falcon Complete dashboard
    FalconComplete {
        #[command(subcommand)]
        action: commands::falcon_complete_dashboard::Action,
    },
    /// Manage Falcon container
    FalconContainer {
        #[command(subcommand)]
        action: commands::falcon_container::Action,
    },
    /// Manage Falcon Intelligence Sandbox
    Sandbox {
        #[command(subcommand)]
        action: commands::falconx_sandbox::Action,
    },
    /// Manage FDR
    Fdr {
        #[command(subcommand)]
        action: commands::fdr::Action,
    },
    /// Manage FileVantage
    Filevantage {
        #[command(subcommand)]
        action: commands::filevantage::Action,
    },
    /// Manage firewall rules
    Firewall {
        #[command(subcommand)]
        action: commands::firewall_management::Action,
    },
    /// Manage firewall policies
    FirewallPolicy {
        #[command(subcommand)]
        action: commands::firewall_policies::Action,
    },
    /// Manage Foundry LogScale
    Logscale {
        #[command(subcommand)]
        action: commands::foundry_logscale::Action,
    },
    /// Manage hosts
    Host {
        #[command(subcommand)]
        action: commands::hosts::Action,
    },
    /// Manage host groups
    HostGroup {
        #[command(subcommand)]
        action: commands::host_group::Action,
    },
    /// Manage host migrations
    HostMigration {
        #[command(subcommand)]
        action: commands::host_migration::Action,
    },
    /// Manage identity protection
    Identity {
        #[command(subcommand)]
        action: commands::identity_protection::Action,
    },
    /// Manage image assessment policies
    ImagePolicy {
        #[command(subcommand)]
        action: commands::image_assessment_policies::Action,
    },
    /// Manage incidents
    Incident {
        #[command(subcommand)]
        action: commands::incidents::Action,
    },
    /// Manage installation tokens
    InstallToken {
        #[command(subcommand)]
        action: commands::installation_tokens::Action,
    },
    /// Manage threat intelligence
    Intel {
        #[command(subcommand)]
        action: commands::intel::Action,
    },
    /// Manage intelligence feeds
    IntelFeed {
        #[command(subcommand)]
        action: commands::intelligence_feeds::Action,
    },
    /// Manage intelligence indicator graph
    IntelGraph {
        #[command(subcommand)]
        action: commands::intelligence_indicator_graph::Action,
    },
    /// Manage IOA exclusions
    IoaExclusion {
        #[command(subcommand)]
        action: commands::ioa_exclusions::Action,
    },
    /// Manage IOC indicators
    Ioc {
        #[command(subcommand)]
        action: commands::ioc::Action,
    },
    /// Manage IOCs (legacy)
    Iocs {
        #[command(subcommand)]
        action: commands::iocs::Action,
    },
    /// Manage IT automation
    ItAutomation {
        #[command(subcommand)]
        action: commands::it_automation::Action,
    },
    /// Manage Kubernetes container compliance
    K8sCompliance {
        #[command(subcommand)]
        action: commands::kubernetes_container_compliance::Action,
    },
    /// Manage Kubernetes protection
    K8s {
        #[command(subcommand)]
        action: commands::kubernetes_protection::Action,
    },
    /// Manage MalQuery
    Malquery {
        #[command(subcommand)]
        action: commands::malquery::Action,
    },
    /// Manage message center
    Message {
        #[command(subcommand)]
        action: commands::message_center::Action,
    },
    /// Manage ML exclusions
    MlExclusion {
        #[command(subcommand)]
        action: commands::ml_exclusions::Action,
    },
    /// Manage mobile enrollment
    Mobile {
        #[command(subcommand)]
        action: commands::mobile_enrollment::Action,
    },
    /// Manage MSSP (Flight Control)
    Mssp {
        #[command(subcommand)]
        action: commands::mssp::Action,
    },
    /// Manage NGSIEM
    Ngsiem {
        #[command(subcommand)]
        action: commands::ngsiem::Action,
    },
    /// Manage OAuth2 tokens
    Oauth2 {
        #[command(subcommand)]
        action: commands::oauth2::Action,
    },
    /// Manage on-demand scans
    Ods {
        #[command(subcommand)]
        action: commands::ods::Action,
    },
    /// Manage OverWatch dashboard
    Overwatch {
        #[command(subcommand)]
        action: commands::overwatch_dashboard::Action,
    },
    /// Manage prevention policies
    PreventionPolicy {
        #[command(subcommand)]
        action: commands::prevention_policies::Action,
    },
    /// Manage quarantined files
    Quarantine {
        #[command(subcommand)]
        action: commands::quarantine::Action,
    },
    /// Manage quick scans
    QuickScan {
        #[command(subcommand)]
        action: commands::quick_scan::Action,
    },
    /// Manage quick scans (pro)
    QuickScanPro {
        #[command(subcommand)]
        action: commands::quick_scan_pro::Action,
    },
    /// Manage real-time response sessions
    Rtr {
        #[command(subcommand)]
        action: commands::real_time_response::Action,
    },
    /// Manage real-time response (admin)
    RtrAdmin {
        #[command(subcommand)]
        action: commands::real_time_response_admin::Action,
    },
    /// Manage real-time response audit
    RtrAudit {
        #[command(subcommand)]
        action: commands::real_time_response_audit::Action,
    },
    /// Manage recon monitoring rules
    Recon {
        #[command(subcommand)]
        action: commands::recon::Action,
    },
    /// Manage report executions
    ReportExecution {
        #[command(subcommand)]
        action: commands::report_executions::Action,
    },
    /// Manage response policies
    ResponsePolicy {
        #[command(subcommand)]
        action: commands::response_policies::Action,
    },
    /// Manage SaaS security
    SaasSecurity {
        #[command(subcommand)]
        action: commands::saas_security::Action,
    },
    /// Manage sample uploads
    Sample {
        #[command(subcommand)]
        action: commands::sample_uploads::Action,
    },
    /// Manage scheduled reports
    ScheduledReport {
        #[command(subcommand)]
        action: commands::scheduled_reports::Action,
    },
    /// Manage sensor downloads
    SensorDownload {
        #[command(subcommand)]
        action: commands::sensor_download::Action,
    },
    /// Manage sensor update policies
    SensorUpdatePolicy {
        #[command(subcommand)]
        action: commands::sensor_update_policies::Action,
    },
    /// Manage sensor usage
    SensorUsage {
        #[command(subcommand)]
        action: commands::sensor_usage::Action,
    },
    /// Manage sensor visibility exclusions
    SvExclusion {
        #[command(subcommand)]
        action: commands::sensor_visibility_exclusions::Action,
    },
    /// Manage serverless vulnerabilities
    ServerlessVuln {
        #[command(subcommand)]
        action: commands::serverless_vulnerabilities::Action,
    },
    /// Manage Spotlight vulnerabilities
    SpotlightVuln {
        #[command(subcommand)]
        action: commands::spotlight_vulnerabilities::Action,
    },
    /// Manage Spotlight evaluation logic
    SpotlightEval {
        #[command(subcommand)]
        action: commands::spotlight_evaluation_logic::Action,
    },
    /// Manage Spotlight vulnerability metadata
    SpotlightMetadata {
        #[command(subcommand)]
        action: commands::spotlight_vulnerability_metadata::Action,
    },
    /// Manage tailored intelligence
    TailoredIntel {
        #[command(subcommand)]
        action: commands::tailored_intelligence::Action,
    },
    /// Manage ThreatGraph
    Threatgraph {
        #[command(subcommand)]
        action: commands::threatgraph::Action,
    },
    /// Manage unidentified containers
    UnidentifiedContainer {
        #[command(subcommand)]
        action: commands::unidentified_containers::Action,
    },
    /// Manage users
    User {
        #[command(subcommand)]
        action: commands::user_management::Action,
    },
    /// Manage workflows
    Workflow {
        #[command(subcommand)]
        action: commands::workflows::Action,
    },
    /// Manage Zero Trust assessments
    ZeroTrust {
        #[command(subcommand)]
        action: commands::zero_trust_assessment::Action,
    },
}
