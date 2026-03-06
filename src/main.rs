mod auth;
mod cli;
mod client;
mod commands;
mod config;
mod error;
mod output;

use clap::Parser;
use cli::{Cli, Command};
use config::Config;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let config = match build_config(&cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let auth = auth::Auth::new(config.clone());
    let falcon = client::FalconClient::new(auth, config.base_url.clone());

    let result = execute(&falcon, cli.command).await;

    match result {
        Ok(value) => {
            output::print_value(&value, &cli.output);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn build_config(cli: &Cli) -> error::Result<Config> {
    let mut config = Config::from_env()?;

    if let Some(ref id) = cli.client_id {
        config.client_id = id.clone();
    }
    if let Some(ref url) = cli.base_url {
        config.base_url = url.clone();
    }
    if cli.member_cid.is_some() {
        config.member_cid = cli.member_cid.clone();
    }

    Ok(config)
}

async fn execute(
    client: &client::FalconClient,
    command: Command,
) -> error::Result<serde_json::Value> {
    match command {
        Command::Alert { action } => commands::alerts::execute(client, action).await,
        Command::ApiIntegration { action } => {
            commands::api_integrations::execute(client, action).await
        }
        Command::Aspm { action } => commands::aspm::execute(client, action).await,
        Command::CaoHunting { action } => commands::cao_hunting::execute(client, action).await,
        Command::Case { action } => commands::case_management::execute(client, action).await,
        Command::CertExclusion { action } => {
            commands::certificate_based_exclusions::execute(client, action).await
        }
        Command::CloudAws { action } => {
            commands::cloud_aws_registration::execute(client, action).await
        }
        Command::CloudAzure { action } => {
            commands::cloud_azure_registration::execute(client, action).await
        }
        Command::CloudConnectAws { action } => {
            commands::cloud_connect_aws::execute(client, action).await
        }
        Command::CloudGcp { action } => {
            commands::cloud_google_cloud_registration::execute(client, action).await
        }
        Command::CloudOci { action } => {
            commands::cloud_oci_registration::execute(client, action).await
        }
        Command::CloudPolicy { action } => commands::cloud_policies::execute(client, action).await,
        Command::CloudSecurity { action } => {
            commands::cloud_security::execute(client, action).await
        }
        Command::CloudAsset { action } => {
            commands::cloud_security_assets::execute(client, action).await
        }
        Command::CloudCompliance { action } => {
            commands::cloud_security_compliance::execute(client, action).await
        }
        Command::CloudDetection { action } => {
            commands::cloud_security_detections::execute(client, action).await
        }
        Command::CloudSnapshot { action } => {
            commands::cloud_snapshots::execute(client, action).await
        }
        Command::ConfigAssessment { action } => {
            commands::configuration_assessment::execute(client, action).await
        }
        Command::ConfigEval { action } => {
            commands::configuration_assessment_evaluation_logic::execute(client, action).await
        }
        Command::ContainerAlert { action } => {
            commands::container_alerts::execute(client, action).await
        }
        Command::ContainerDetection { action } => {
            commands::container_detections::execute(client, action).await
        }
        Command::ContainerCompliance { action } => {
            commands::container_image_compliance::execute(client, action).await
        }
        Command::ContainerImage { action } => {
            commands::container_images::execute(client, action).await
        }
        Command::ContainerPackage { action } => {
            commands::container_packages::execute(client, action).await
        }
        Command::ContainerVuln { action } => {
            commands::container_vulnerabilities::execute(client, action).await
        }
        Command::ContentUpdatePolicy { action } => {
            commands::content_update_policies::execute(client, action).await
        }
        Command::CorrelationRule { action } => {
            commands::correlation_rules::execute(client, action).await
        }
        Command::CorrelationAdmin { action } => {
            commands::correlation_rules_admin::execute(client, action).await
        }
        Command::Cspm { action } => commands::cspm_registration::execute(client, action).await,
        Command::CustomIoa { action } => commands::custom_ioa::execute(client, action).await,
        Command::CustomStorage { action } => {
            commands::custom_storage::execute(client, action).await
        }
        Command::D4c { action } => commands::d4c_registration::execute(client, action).await,
        Command::DataProtection { action } => {
            commands::data_protection_configuration::execute(client, action).await
        }
        Command::Datascanner { action } => commands::datascanner::execute(client, action).await,
        Command::DeliverySetting { action } => {
            commands::delivery_settings::execute(client, action).await
        }
        Command::Deployment { action } => commands::deployments::execute(client, action).await,
        Command::Detection { action } => commands::detects::execute(client, action).await,
        Command::DeviceContent { action } => {
            commands::device_content::execute(client, action).await
        }
        Command::DeviceControlPolicy { action } => {
            commands::device_control_policies::execute(client, action).await
        }
        Command::Discover { action } => commands::discover::execute(client, action).await,
        Command::Download { action } => commands::downloads::execute(client, action).await,
        Command::Drift { action } => commands::drift_indicators::execute(client, action).await,
        Command::EventStream { action } => commands::event_streams::execute(client, action).await,
        Command::Exposure { action } => {
            commands::exposure_management::execute(client, action).await
        }
        Command::Faas { action } => commands::faas_execution::execute(client, action).await,
        Command::FalconComplete { action } => {
            commands::falcon_complete_dashboard::execute(client, action).await
        }
        Command::FalconContainer { action } => {
            commands::falcon_container::execute(client, action).await
        }
        Command::Sandbox { action } => commands::falconx_sandbox::execute(client, action).await,
        Command::Fdr { action } => commands::fdr::execute(client, action).await,
        Command::Filevantage { action } => commands::filevantage::execute(client, action).await,
        Command::Firewall { action } => {
            commands::firewall_management::execute(client, action).await
        }
        Command::FirewallPolicy { action } => {
            commands::firewall_policies::execute(client, action).await
        }
        Command::Logscale { action } => commands::foundry_logscale::execute(client, action).await,
        Command::Host { action } => commands::hosts::execute(client, action).await,
        Command::HostGroup { action } => commands::host_group::execute(client, action).await,
        Command::HostMigration { action } => {
            commands::host_migration::execute(client, action).await
        }
        Command::Identity { action } => {
            commands::identity_protection::execute(client, action).await
        }
        Command::ImagePolicy { action } => {
            commands::image_assessment_policies::execute(client, action).await
        }
        Command::Incident { action } => commands::incidents::execute(client, action).await,
        Command::InstallToken { action } => {
            commands::installation_tokens::execute(client, action).await
        }
        Command::Intel { action } => commands::intel::execute(client, action).await,
        Command::IntelFeed { action } => {
            commands::intelligence_feeds::execute(client, action).await
        }
        Command::IntelGraph { action } => {
            commands::intelligence_indicator_graph::execute(client, action).await
        }
        Command::IoaExclusion { action } => commands::ioa_exclusions::execute(client, action).await,
        Command::Ioc { action } => commands::ioc::execute(client, action).await,
        Command::Iocs { action } => commands::iocs::execute(client, action).await,
        Command::ItAutomation { action } => commands::it_automation::execute(client, action).await,
        Command::K8sCompliance { action } => {
            commands::kubernetes_container_compliance::execute(client, action).await
        }
        Command::K8s { action } => commands::kubernetes_protection::execute(client, action).await,
        Command::Malquery { action } => commands::malquery::execute(client, action).await,
        Command::Message { action } => commands::message_center::execute(client, action).await,
        Command::MlExclusion { action } => commands::ml_exclusions::execute(client, action).await,
        Command::Mobile { action } => commands::mobile_enrollment::execute(client, action).await,
        Command::Mssp { action } => commands::mssp::execute(client, action).await,
        Command::Ngsiem { action } => commands::ngsiem::execute(client, action).await,
        Command::Oauth2 { action } => commands::oauth2::execute(client, action).await,
        Command::Ods { action } => commands::ods::execute(client, action).await,
        Command::Overwatch { action } => {
            commands::overwatch_dashboard::execute(client, action).await
        }
        Command::PreventionPolicy { action } => {
            commands::prevention_policies::execute(client, action).await
        }
        Command::Quarantine { action } => commands::quarantine::execute(client, action).await,
        Command::QuickScan { action } => commands::quick_scan::execute(client, action).await,
        Command::QuickScanPro { action } => commands::quick_scan_pro::execute(client, action).await,
        Command::Rtr { action } => commands::real_time_response::execute(client, action).await,
        Command::RtrAdmin { action } => {
            commands::real_time_response_admin::execute(client, action).await
        }
        Command::RtrAudit { action } => {
            commands::real_time_response_audit::execute(client, action).await
        }
        Command::Recon { action } => commands::recon::execute(client, action).await,
        Command::ReportExecution { action } => {
            commands::report_executions::execute(client, action).await
        }
        Command::ResponsePolicy { action } => {
            commands::response_policies::execute(client, action).await
        }
        Command::SaasSecurity { action } => commands::saas_security::execute(client, action).await,
        Command::Sample { action } => commands::sample_uploads::execute(client, action).await,
        Command::ScheduledReport { action } => {
            commands::scheduled_reports::execute(client, action).await
        }
        Command::SensorDownload { action } => {
            commands::sensor_download::execute(client, action).await
        }
        Command::SensorUpdatePolicy { action } => {
            commands::sensor_update_policies::execute(client, action).await
        }
        Command::SensorUsage { action } => commands::sensor_usage::execute(client, action).await,
        Command::SvExclusion { action } => {
            commands::sensor_visibility_exclusions::execute(client, action).await
        }
        Command::ServerlessVuln { action } => {
            commands::serverless_vulnerabilities::execute(client, action).await
        }
        Command::SpotlightVuln { action } => {
            commands::spotlight_vulnerabilities::execute(client, action).await
        }
        Command::SpotlightEval { action } => {
            commands::spotlight_evaluation_logic::execute(client, action).await
        }
        Command::SpotlightMetadata { action } => {
            commands::spotlight_vulnerability_metadata::execute(client, action).await
        }
        Command::TailoredIntel { action } => {
            commands::tailored_intelligence::execute(client, action).await
        }
        Command::Threatgraph { action } => commands::threatgraph::execute(client, action).await,
        Command::UnidentifiedContainer { action } => {
            commands::unidentified_containers::execute(client, action).await
        }
        Command::User { action } => commands::user_management::execute(client, action).await,
        Command::Workflow { action } => commands::workflows::execute(client, action).await,
        Command::ZeroTrust { action } => {
            commands::zero_trust_assessment::execute(client, action).await
        }
    }
}
