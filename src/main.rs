mod auth;
mod cli;
mod client;
mod commands;
mod config;
mod daemon;
mod dispatch;
mod error;
mod output;

use clap::Parser;
use cli::{Cli, Command, DaemonAction};
use config::Config;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Handle daemon subcommand.
    if let Command::Daemon { action } = &cli.command {
        handle_daemon_command(action, &cli).await;
        return;
    }

    // If --daemon flag is set, route through the daemon client.
    if cli.daemon {
        handle_daemon_client(&cli).await;
        return;
    }

    // Direct mode: call API directly.
    let config = match build_config(&cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let auth = auth::Auth::new(config.clone());
    let falcon = client::FalconClient::new(auth, config.base_url.clone());

    let result = dispatch::execute(&falcon, cli.command).await;

    match result {
        Ok(value) => {
            output::print_value(&value, &cli.output, cli.pretty);
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

async fn handle_daemon_command(action: &DaemonAction, cli: &Cli) {
    match action {
        DaemonAction::Start { socket, config } => {
            let config_obj = match build_config(cli) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            let auth = auth::Auth::new(config_obj.clone());
            let falcon = client::FalconClient::new(auth, config_obj.base_url.clone());
            let falcon = Arc::new(falcon);

            let socket_path = daemon::resolve_socket_path(socket.as_deref());
            let config_path = config.as_ref().map(std::path::PathBuf::from);

            if let Err(e) =
                daemon::server::start(falcon, &socket_path, config_path.as_deref()).await
            {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        DaemonAction::Stop { socket } => {
            let socket_path = daemon::resolve_socket_path(socket.as_deref());
            if let Err(e) = daemon::client::stop(&socket_path) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        DaemonAction::Status { socket } => {
            let socket_path = daemon::resolve_socket_path(socket.as_deref());
            let status = daemon::client::status(&socket_path).await;
            let json = serde_json::to_string_pretty(&status).unwrap();
            println!("{}", json);
        }
    }
}

async fn handle_daemon_client(cli: &Cli) {
    let socket_path = daemon::resolve_socket_path(cli.socket.as_deref());

    let token = match &cli.token {
        Some(t) => t.clone(),
        None => {
            eprintln!("Error: FALCON_DAEMON_TOKEN is required when using --daemon");
            eprintln!("hint: eval \"$(falcon-cli daemon start)\" to set it");
            std::process::exit(1);
        }
    };

    // Extract command and action from CLI args.
    let (command, action, args) = match extract_command_args(&cli.command) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let result = daemon::client::send_command(&socket_path, token, command, action, args).await;

    match result {
        Ok(value) => {
            output::print_value(&value, &cli.output, cli.pretty);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Extract command name, action name, and arguments from the parsed Command enum.
/// This reconstructs what the daemon needs to dispatch the command.
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
        if arg == "--daemon" || arg == "--pretty" {
            i += 1;
            continue;
        }
        if arg == "--client-id"
            || arg == "--base-url"
            || arg == "--member-cid"
            || arg == "--output"
            || arg == "--socket"
            || arg == "--token"
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
