mod agent;
mod auth;
mod cli;
mod client;
mod commands;
mod config;
mod dispatch;
mod error;
mod output;

use clap::Parser;
use cli::{AgentAction, Cli, Command};
use config::Config;
use std::collections::HashMap;
use std::sync::Arc;

fn main() {
    let cli = Cli::parse();

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
        handle_agent_start(&cli, socket.as_deref(), config.as_deref(), *foreground);
        return;
    }

    // All other paths use the tokio runtime.
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async_main(cli));
}

async fn async_main(cli: Cli) {
    // Handle agent subcommands (stop, status).
    if let Command::Agent { action } = &cli.command {
        handle_agent_command(action, &cli).await;
        return;
    }

    // If FALCON_AGENT_TOKEN is set, route through the agent automatically.
    if cli.token.is_some() {
        handle_agent_client(&cli).await;
        return;
    }

    // Direct mode: call API directly.
    let config = match build_config(&cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("hint: to use agent mode: eval \"$(falcon-cli agent start)\"");
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

/// Handle `agent start` before tokio runtime is created.
/// This allows fork() to run in a single-threaded process.
fn handle_agent_start(cli: &Cli, socket: Option<&str>, config: Option<&str>, foreground: bool) {
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

    let socket_path = agent::resolve_socket_path(socket);
    let config_path = config.map(std::path::PathBuf::from);

    if let Err(e) = agent::server::start(falcon, &socket_path, config_path.as_deref(), foreground) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Handle agent subcommands other than `start` (stop, status).
async fn handle_agent_command(action: &AgentAction, _cli: &Cli) {
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
            } else {
                let socket_path = agent::resolve_socket_path(socket.as_deref());
                if let Err(e) = agent::client::stop(&socket_path) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        AgentAction::Status { socket } => {
            let socket_path = agent::resolve_socket_path(socket.as_deref());
            let status = agent::client::status(&socket_path).await;
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
            output::print_value(&value, &cli.output, cli.pretty);
        }
        Err(e) => {
            eprintln!("Error (via agent at {}): {}", socket_path.display(), e);
            eprintln!("hint: is the agent running? check with: falcon-cli agent status");
            std::process::exit(1);
        }
    }
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
        if arg == "--pretty" {
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
