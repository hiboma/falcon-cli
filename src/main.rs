mod agent;
mod auth;
mod cli;
mod client;
mod commands;
mod config;
mod dispatch;
mod error;
mod output;
mod profile;

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{CommandFactory, Parser};
use cli::{AgentAction, Cli, Command, ProfileAction};
use config::FalconCredentials;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

fn main() {
    // If top-level --help is requested, show profile-aware help and exit.
    if should_show_profile_help() {
        show_profile_help();
        return;
    }

    let cli = Cli::parse();

    // Handle shell completion generation early (no auth, no agent, no tokio needed).
    if let Command::Completion { shell } = cli.command {
        clap_complete::generate(
            shell,
            &mut Cli::command(),
            "falcon-cli",
            &mut std::io::stdout(),
        );
        return;
    }

    // Handle credentials store management early. We skip resolve() entirely
    // because resolve() consults the OS credential store, which may prompt
    // or fail with an ACL error — the whole point of `credentials status`
    // is to tell the user about the store, not to be polluted by it.
    if let Command::Credentials { ref action } = cli.command {
        if let Err(e) = commands::credentials::handle(action) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Resolve credentials early (before fork).
    let credentials = FalconCredentials::resolve(
        cli.client_id.as_deref(),
        cli.base_url.as_deref(),
        cli.member_cid.as_deref(),
    );

    // Handle `agent start` before tokio runtime is created.
    // fork() requires a single-threaded process; tokio spawns worker threads.
    if let Command::Agent {
        action:
            AgentAction::Start {
                socket,
                config,
                foreground,
            },
    } = &cli.command
    {
        handle_agent_start(
            socket.as_deref(),
            config.as_deref(),
            *foreground,
            credentials,
        );
        return;
    }

    // All other paths use the tokio runtime.
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async_main(cli, credentials));
}

async fn async_main(cli: Cli, credentials: FalconCredentials) {
    // Handle profile subcommands.
    if let Command::Profile { action } = &cli.command {
        handle_profile_command(action, cli.profile.as_deref());
        return;
    }

    // Handle agent subcommands (stop, status).
    if let Command::Agent { action } = &cli.command {
        handle_agent_command(action).await;
        return;
    }

    // If FALCON_AGENT_TOKEN is set, route through the agent automatically.
    if !cli.no_agent && cli.token.is_some() {
        handle_agent_client(&cli).await;
        return;
    }

    // If no explicit token but a session file exists, use it for auto-detection.
    if !cli.no_agent && cli.token.is_none() {
        if let Some(session) = agent::session::read_session() {
            if agent::session::is_session_alive(&session) {
                handle_agent_client_from_session(&cli, session).await;
                return;
            }
        }
    }

    // Check profile restrictions before dispatching.
    if let Some(ref active_profile) = profile::resolve(cli.profile.as_deref()) {
        let cmd_name = command_name_from(&cli.command);
        if !active_profile.is_command_allowed(&cmd_name) {
            eprintln!(
                "Error: command '{}' is not allowed by profile '{}'",
                cmd_name, active_profile.name
            );
            eprintln!(
                "hint: use --profile to switch profiles, or run 'falcon-cli profile list' to see available profiles"
            );
            std::process::exit(1);
        }
    }

    // Direct mode: call API directly using resolved credentials.
    let config = match credentials.to_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("hint: to use agent mode: falcon-cli agent start");
            std::process::exit(1);
        }
    };

    let auth = auth::Auth::new(config.clone());
    let falcon = client::FalconClient::new(auth, config.base_url.clone()).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    let result = dispatch::execute(&falcon, cli.command).await;

    match result {
        Ok(value) => {
            if is_binary_response(&value) {
                write_binary_response(&value);
            } else {
                output::print_value(&value, &cli.output, cli.pretty);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Check if top-level --help/-h is requested (not for a subcommand).
fn should_show_profile_help() -> bool {
    let args: Vec<String> = std::env::args().collect();
    // Only intercept if -h/--help appears at top level (no subcommand before it).
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-h" || arg == "--help" {
            return true;
        }
        // If we hit a non-flag argument, it's a subcommand — don't intercept.
        if !arg.starts_with('-') {
            return false;
        }
        // Skip flags with values.
        if matches!(
            arg.as_str(),
            "--client-id"
                | "--base-url"
                | "--member-cid"
                | "--output"
                | "--socket"
                | "--token"
                | "--profile"
        ) {
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

/// Show profile-aware help text.
fn show_profile_help() {
    // Extract --profile value from args.
    let args: Vec<String> = std::env::args().collect();
    let mut cli_profile = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--profile" {
            if i + 1 < args.len() {
                cli_profile = Some(args[i + 1].clone());
            }
            break;
        }
        if args[i].starts_with("--profile=") {
            cli_profile = Some(args[i].trim_start_matches("--profile=").to_string());
            break;
        }
        i += 1;
    }

    let active = profile::resolve(cli_profile.as_deref());

    match active {
        Some(ref ap) if !ap.commands.iter().any(|c| c == "*") => {
            print_filtered_help(ap);
        }
        _ => {
            // No profile or wildcard: show default help.
            let mut cmd = Cli::command();
            let help = cmd.render_help();
            print!("{}", help);
        }
    }
}

/// Print help text filtered by the active profile.
fn print_filtered_help(ap: &profile::ActiveProfile) {
    let version = env!("CARGO_PKG_VERSION");
    let total = total_command_count();
    let allowed = ap.commands.len();

    println!("A CLI tool for CrowdStrike Falcon API");
    println!();
    println!("Usage: falcon-cli [OPTIONS] <COMMAND>");
    println!();

    // Options section — use clap to render them.
    let cmd = Cli::command();
    println!("Options:");
    for arg in cmd.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }
        let long = arg
            .get_long()
            .map(|l| format!("--{}", l))
            .unwrap_or_default();
        let short = arg
            .get_short()
            .map(|s| format!("-{}, ", s))
            .unwrap_or_else(|| "    ".to_string());
        let is_bool = arg.get_action().takes_values();
        let value_name = if !is_bool {
            String::new()
        } else {
            arg.get_value_names()
                .map(|v| {
                    v.iter()
                        .map(|n| format!("<{}>", n))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
        };
        let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
        if long.is_empty() && value_name.is_empty() {
            continue;
        }
        let flag = if value_name.is_empty() {
            format!("  {}{}", short, long)
        } else {
            format!("  {}{} {}", short, long, value_name)
        };
        println!("{:<40} {}", flag, help);
    }
    println!();

    // Commands section — group by category, only showing allowed commands.
    let categories: &[(&str, &[&str])] = &[
        (
            "Detection & Response",
            &[
                "alert",
                "detection",
                "incident",
                "rtr",
                "rtr-admin",
                "rtr-audit",
                "recon",
                "overwatch",
                "sandbox",
                "quarantine",
                "drift",
            ],
        ),
        (
            "Host Management",
            &[
                "host",
                "host-group",
                "host-migration",
                "discover",
                "device-content",
                "device-control-policy",
            ],
        ),
        (
            "Policy Management",
            &[
                "prevention-policy",
                "response-policy",
                "sensor-update-policy",
                "content-update-policy",
                "firewall-policy",
            ],
        ),
        (
            "Cloud Security",
            &[
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
                "cspm",
                "d4c",
            ],
        ),
        (
            "Container & Kubernetes",
            &[
                "container-alert",
                "container-detection",
                "container-compliance",
                "container-image",
                "container-package",
                "container-vuln",
                "falcon-container",
                "k8s",
                "k8s-compliance",
                "unidentified-container",
                "image-policy",
            ],
        ),
        (
            "Vulnerability Management",
            &[
                "spotlight-vuln",
                "spotlight-eval",
                "spotlight-metadata",
                "serverless-vuln",
                "exposure",
                "config-assessment",
                "config-eval",
            ],
        ),
        (
            "Exclusions & IOC",
            &[
                "ioa-exclusion",
                "ioc",
                "iocs",
                "ml-exclusion",
                "sv-exclusion",
                "cert-exclusion",
                "custom-ioa",
            ],
        ),
        (
            "Threat Intelligence",
            &[
                "intel",
                "intel-feed",
                "intel-graph",
                "tailored-intel",
                "threatgraph",
                "malquery",
            ],
        ),
        (
            "Sensor & Downloads",
            &[
                "sensor-download",
                "sensor-usage",
                "install-token",
                "download",
                "deployment",
            ],
        ),
        (
            "Scanning & Compliance",
            &[
                "quick-scan",
                "quick-scan-pro",
                "ods",
                "filevantage",
                "datascanner",
                "data-protection",
            ],
        ),
        (
            "Identity & Access",
            &["identity", "user", "oauth2", "zero-trust", "mobile", "mssp"],
        ),
        (
            "Monitoring & Reporting",
            &[
                "event-stream",
                "message",
                "report-execution",
                "scheduled-report",
                "case",
                "falcon-complete",
                "workflow",
                "it-automation",
            ],
        ),
        (
            "Platform & Integration",
            &[
                "api-integration",
                "aspm",
                "cao-hunting",
                "correlation-rule",
                "correlation-admin",
                "custom-storage",
                "delivery-setting",
                "fdr",
                "firewall",
                "logscale",
                "ngsiem",
                "sample",
                "saas-security",
                "faas",
            ],
        ),
    ];

    println!("Commands:");
    for (category, cmds) in categories {
        let filtered: Vec<&&str> = cmds.iter().filter(|c| ap.is_command_allowed(c)).collect();
        if filtered.is_empty() {
            continue;
        }
        println!();
        println!("{}:", category);
        let line = filtered
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {}", line);
    }

    // Always show agent, profile, completion.
    println!();
    println!("Agent:");
    println!("  agent");
    println!();
    println!("Configuration:");
    println!("  profile");

    println!();
    println!(
        "Active profile: {} ({}/{} commands)",
        ap.name, allowed, total,
    );
    println!("Version: {}", version);
}

/// Handle `agent start` before tokio runtime is created.
/// This allows fork() to run in a single-threaded process.
fn handle_agent_start(
    socket: Option<&str>,
    config: Option<&str>,
    foreground: bool,
    credentials: FalconCredentials,
) {
    if let Err(e) = credentials.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let config_obj = match credentials.to_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let auth = auth::Auth::new(config_obj.clone());
    let falcon = client::FalconClient::new(auth, config_obj.base_url.clone()).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });
    let falcon = Arc::new(falcon);

    let socket_path = match socket {
        Some(p) => std::path::PathBuf::from(p),
        None => agent::generate_socket_path(),
    };
    let config_path = config.map(std::path::PathBuf::from);

    // Clear credential environment variables before fork.
    // The child process will use the FalconCredentials struct instead.
    // SAFETY: Single-threaded context (before tokio runtime creation).
    unsafe {
        FalconCredentials::clear_env();
    }

    if let Err(e) = agent::server::start(
        falcon,
        &socket_path,
        config_path.as_deref(),
        foreground,
        credentials,
    ) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Handle agent subcommands other than `start` (stop, status).
async fn handle_agent_command(action: &AgentAction) {
    match action {
        AgentAction::Start { .. } => {
            // Handled in main() before tokio runtime.
            unreachable!("agent start should be handled before tokio runtime");
        }
        AgentAction::Stop { socket, all } => {
            if *all {
                if let Err(e) = agent::client::stop_all() {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            } else if let Some(s) = socket {
                if let Err(e) = agent::client::stop(&std::path::PathBuf::from(s)) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            } else if let Err(e) = agent::client::stop_from_session() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        AgentAction::Status => {
            let status = agent::client::status().await;
            let json = serde_json::to_string_pretty(&status)
                .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));
            println!("{}", json);
        }
    }
}

async fn handle_agent_client(cli: &Cli) {
    let socket_path = agent::resolve_socket_path(cli.socket.as_deref());

    // token is guaranteed to be Some here (checked in async_main).
    let token = cli.token.clone().unwrap();

    // Extract command and action from CLI args.
    let (command, action, args) = match extract_command_args(&cli.command) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let result = agent::client::send_command(&socket_path, token, command, action, args).await;

    match result {
        Ok(value) => {
            if is_binary_response(&value) {
                write_binary_response(&value);
            } else {
                output::print_value(&value, &cli.output, cli.pretty);
            }
        }
        Err(e) => {
            eprintln!("Error (via agent at {}): {}", socket_path.display(), e);
            eprintln!("hint: is the agent running? check with: falcon-cli agent status");
            std::process::exit(1);
        }
    }
}

async fn handle_agent_client_from_session(cli: &Cli, session: agent::session::SessionInfo) {
    let socket_path = std::path::PathBuf::from(&session.socket_path);
    let token = session.token;

    let (command, action, args) = match extract_command_args(&cli.command) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let result = agent::client::send_command(&socket_path, token, command, action, args).await;

    match result {
        Ok(value) => {
            if is_binary_response(&value) {
                write_binary_response(&value);
            } else {
                output::print_value(&value, &cli.output, cli.pretty);
            }
        }
        Err(e) => {
            eprintln!("Error (via agent at {}): {}", socket_path.display(), e);
            eprintln!("hint: is the agent running? check with: falcon-cli agent status");
            std::process::exit(1);
        }
    }
}

/// Handle `profile init` and `profile list` subcommands.
fn handle_profile_command(action: &ProfileAction, cli_profile: Option<&str>) {
    match action {
        ProfileAction::Init { global } => {
            let path = if *global {
                let home = std::env::var("HOME").unwrap_or_else(|_| {
                    eprintln!("Error: HOME is not set");
                    std::process::exit(1);
                });
                let dir = std::path::PathBuf::from(home).join(".config/falcon-cli");
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    eprintln!("Error: failed to create {}: {}", dir.display(), e);
                    std::process::exit(1);
                }
                dir.join("config.toml")
            } else {
                std::path::PathBuf::from(".falcon-cli.toml")
            };

            if path.exists() {
                eprintln!("Error: {} already exists", path.display());
                eprintln!("hint: remove or rename the file to re-initialize");
                std::process::exit(1);
            }

            if let Err(e) = std::fs::write(&path, profile::builtin_config_toml()) {
                eprintln!("Error: failed to write {}: {}", path.display(), e);
                std::process::exit(1);
            }
            println!("Created {}", path.display());
        }
        ProfileAction::List => {
            let config = profile::load_config();
            let active = profile::resolve(cli_profile);

            match config {
                Some(config) if !config.profiles.is_empty() => {
                    let active_name = active.as_ref().map(|a| a.name.as_str());
                    for (name, p) in &config.profiles {
                        let marker = if Some(name.as_str()) == active_name {
                            " (active)"
                        } else {
                            ""
                        };
                        let cmd_count = if p.commands.iter().any(|c| c == "*") {
                            "all".to_string()
                        } else {
                            format!("{} commands", p.commands.len())
                        };
                        println!("  {}{} - {} [{}]", name, marker, p.description, cmd_count);
                    }
                    if let Some(ref ap) = active {
                        let total = total_command_count();
                        let allowed = if ap.commands.iter().any(|c| c == "*") {
                            total
                        } else {
                            ap.commands.len()
                        };
                        println!(
                            "\nActive profile: {} - {} ({}/{} commands)",
                            ap.name, ap.description, allowed, total,
                        );
                    }
                }
                _ => {
                    println!("No profiles configured.");
                    println!("hint: run 'falcon-cli profile init' to create a configuration file");
                }
            }
        }
    }
}

/// Get the total number of API commands (excluding agent, profile, completion).
fn total_command_count() -> usize {
    let cmd = Cli::command();
    cmd.get_subcommands()
        .filter(|s| {
            let name = s.get_name();
            name != "agent" && name != "profile" && name != "completion"
        })
        .count()
}

/// Extract the kebab-case command name from a parsed Command variant.
fn command_name_from(command: &Command) -> String {
    // Use the Debug representation to get the variant name, then convert to kebab-case.
    let debug = format!("{:?}", command);
    let variant = debug.split([' ', '{', '(']).next().unwrap_or("");
    to_kebab_case(variant)
}

/// Convert PascalCase to kebab-case (e.g., "CloudAws" → "cloud-aws").
fn to_kebab_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('-');
        }
        result.push(c.to_ascii_lowercase());
    }
    result
}

/// Extract command name, action name, and arguments from the parsed Command enum.
/// This reconstructs what the agent needs to dispatch the command.
fn extract_command_args(
    _command: &Command,
) -> error::Result<(String, String, HashMap<String, serde_json::Value>)> {
    // Serialize the Command to JSON, then extract the structure.
    // Since Command uses clap Subcommand derive, we use the Debug representation
    // to extract names. For a cleaner approach, we re-parse from std::env::args.
    let raw_args: Vec<String> = std::env::args().collect();

    // Find the command and action positions by skipping global flags.
    let mut command_name = String::new();
    let mut action_name = String::new();
    let mut extra_args: HashMap<String, serde_json::Value> = HashMap::new();

    let mut i = 1; // skip binary name
                   // Skip global flags.
    while i < raw_args.len() {
        let arg = &raw_args[i];
        if arg == "--pretty" || arg == "--no-agent" {
            i += 1;
            continue;
        }
        if arg == "--client-id"
            || arg == "--base-url"
            || arg == "--member-cid"
            || arg == "--output"
            || arg == "--socket"
            || arg == "--token"
            || arg == "--profile"
        {
            i += 2; // skip flag and its value
            continue;
        }
        if arg.starts_with("--") {
            // Could be a --flag=value form for global flags.
            if arg.contains('=') {
                let key = arg.split('=').next().unwrap();
                if matches!(
                    key,
                    "--client-id"
                        | "--base-url"
                        | "--member-cid"
                        | "--output"
                        | "--socket"
                        | "--token"
                        | "--profile"
                ) {
                    i += 1;
                    continue;
                }
            }
            break;
        }
        break;
    }

    // Now raw_args[i] should be the command name.
    if i < raw_args.len() {
        command_name = raw_args[i].clone();
        i += 1;
    }

    // raw_args[i] should be the action name.
    if i < raw_args.len() && !raw_args[i].starts_with('-') {
        action_name = raw_args[i].clone();
        i += 1;
    }

    // Remaining args are command-specific flags.
    while i < raw_args.len() {
        let arg = &raw_args[i];
        if arg.starts_with("--") {
            let key = arg.trim_start_matches("--").to_string();

            if arg.contains('=') {
                let parts: Vec<&str> = arg.splitn(2, '=').collect();
                let k = parts[0].trim_start_matches("--").to_string();
                let v = parts[1].to_string();
                insert_arg(&mut extra_args, k, v);
                i += 1;
            } else if i + 1 < raw_args.len() && !raw_args[i + 1].starts_with("--") {
                let value = raw_args[i + 1].clone();
                insert_arg(&mut extra_args, key, value);
                i += 2;
            } else {
                // Boolean flag.
                extra_args.insert(key, serde_json::Value::Bool(true));
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    if command_name.is_empty() {
        return Err(error::FalconError::Config(
            "no command specified".to_string(),
        ));
    }
    if action_name.is_empty() {
        return Err(error::FalconError::Config(
            "no action specified".to_string(),
        ));
    }

    Ok((command_name, action_name, extra_args))
}

/// Insert an argument, converting to an array if the key already exists (e.g. --id a --id b).
fn insert_arg(args: &mut HashMap<String, serde_json::Value>, key: String, value: String) {
    if let Some(existing) = args.get_mut(&key) {
        match existing {
            serde_json::Value::Array(arr) => {
                arr.push(serde_json::Value::String(value));
            }
            _ => {
                let prev = existing.clone();
                *existing = serde_json::json!([prev, value]);
            }
        }
    } else {
        args.insert(key, serde_json::Value::String(value));
    }
}

/// Check if a response contains binary data encoded as base64.
fn is_binary_response(value: &serde_json::Value) -> bool {
    value.get("_binary").and_then(|v| v.as_bool()) == Some(true)
}

/// Decode base64 binary data from a response and write to file or stdout.
fn write_binary_response(value: &serde_json::Value) {
    let encoded = match value.get("data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            eprintln!("Error: binary response missing data field");
            std::process::exit(1);
        }
    };

    let data = match STANDARD.decode(encoded) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to decode binary data: {}", e);
            std::process::exit(1);
        }
    };

    let output_path = value.get("output").and_then(|v| v.as_str());

    match output_path {
        Some(file_path) => {
            if let Err(e) = std::fs::write(file_path, &data) {
                eprintln!("Error: failed to write {}: {}", file_path, e);
                std::process::exit(1);
            }
            eprintln!("Downloaded {} bytes to {}", data.len(), file_path);
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            if let Err(e) = stdout.write_all(&data) {
                eprintln!("Error: failed to write stdout: {}", e);
                std::process::exit(1);
            }
        }
    }
}
