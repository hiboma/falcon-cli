use crate::daemon::handler::RequestHandler;
use crate::daemon::protocol::DaemonRequest;
use crate::daemon::security::{CommandWhitelist, RateLimiter, SecurityConfig};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;

/// Maximum size of a single request line (1 MiB).
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

/// Maximum number of concurrent connections.
const MAX_CONNECTIONS: usize = 64;

/// Start the daemon server.
pub async fn start(
    falcon_client: Arc<crate::client::FalconClient>,
    socket_path: &Path,
    config_path: Option<&Path>,
) -> crate::error::Result<()> {
    // Load security config.
    let security_config = match config_path {
        Some(p) => SecurityConfig::load(p),
        None => {
            let default_path = dirs_config_path();
            SecurityConfig::load(&default_path)
        }
    };

    let whitelist = Arc::new(CommandWhitelist::new(
        &security_config.security.allowed_commands,
    ));
    let rate_limiter = Arc::new(RateLimiter::new(
        security_config.security.rate_limit_per_minute,
    ));

    // Ensure socket directory exists with restricted permissions.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            crate::error::FalconError::Config(format!(
                "failed to create socket directory {}: {}",
                parent.display(),
                e
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| {
                    crate::error::FalconError::Config(format!(
                        "failed to set directory permissions: {}",
                        e
                    ))
                },
            )?;
        }
    }

    // Remove stale socket file.
    match std::fs::remove_file(socket_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(crate::error::FalconError::Config(format!(
                "failed to remove stale socket {}: {}",
                socket_path.display(),
                e
            )));
        }
    }

    // Bind the Unix listener.
    let listener = UnixListener::bind(socket_path).map_err(|e| {
        crate::error::FalconError::Config(format!(
            "failed to bind socket {}: {}",
            socket_path.display(),
            e
        ))
    })?;

    // Set socket file permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| {
                crate::error::FalconError::Config(format!(
                    "failed to set socket permissions: {}",
                    e
                ))
            },
        )?;
    }

    // Write PID file.
    let pid_path = crate::daemon::resolve_pid_path(socket_path);
    std::fs::write(&pid_path, std::process::id().to_string()).map_err(|e| {
        crate::error::FalconError::Config(format!("failed to write PID file: {}", e))
    })?;

    // Generate session token.
    let session_token = crate::daemon::generate_token();

    let handler = Arc::new(RequestHandler::new(
        falcon_client,
        whitelist,
        rate_limiter,
        session_token.clone(),
    ));
    let start_time = std::time::Instant::now();

    // Output SSH Agent-style shell commands to stdout for `eval`.
    println!(
        "FALCON_DAEMON_SOCKET={}; export FALCON_DAEMON_SOCKET;",
        socket_path.display()
    );
    println!(
        "FALCON_DAEMON_TOKEN={}; export FALCON_DAEMON_TOKEN;",
        session_token
    );
    println!("echo daemon started, pid {};", std::process::id());

    eprintln!("daemon: listening on {}", socket_path.display());
    eprintln!("daemon: PID {}", std::process::id());

    // Accept loop with graceful shutdown on SIGTERM/SIGINT.
    let socket_path_owned = socket_path.to_owned();
    let pid_path_owned = pid_path.clone();

    tokio::select! {
        _ = accept_loop(&listener, handler, start_time) => {}
        _ = shutdown_signal() => {
            eprintln!("daemon: shutting down");
        }
    }

    // Cleanup.
    let _ = std::fs::remove_file(&socket_path_owned);
    let _ = std::fs::remove_file(&pid_path_owned);
    eprintln!("daemon: stopped");

    Ok(())
}

async fn accept_loop(
    listener: &UnixListener,
    handler: Arc<RequestHandler>,
    _start_time: std::time::Instant,
) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // Verify peer UID.
                #[cfg(unix)]
                {
                    let peer_uid = stream.peer_cred().ok().map(|cred| cred.uid());
                    if !crate::daemon::security::verify_peer_uid(peer_uid) {
                        eprintln!("daemon: rejected connection from unauthorized UID");
                        continue;
                    }
                }

                // Verify peer process (code signature on macOS, path match on Linux).
                match crate::daemon::peer_verify::verify_peer(&stream) {
                    Ok(verification) => {
                        if !verification.signature_valid {
                            eprintln!(
                                "daemon: rejected connection from unverified binary pid={} path={}",
                                verification.pid, verification.exe_path,
                            );
                            continue;
                        }
                        eprintln!(
                            "daemon: accepted connection pid={} path={}",
                            verification.pid, verification.exe_path,
                        );
                    }
                    Err(e) => {
                        eprintln!("daemon: peer verification failed: {}", e);
                        continue;
                    }
                }

                let handler = handler.clone();
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("daemon: rejected connection, max connections reached");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, handler).await {
                        eprintln!("daemon: connection error: {}", e);
                    }
                    drop(permit);
                });
            }
            Err(e) => {
                eprintln!("daemon: accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    handler: Arc<RequestHandler>,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 {
            // Connection closed.
            break;
        }

        if n > MAX_REQUEST_SIZE {
            let error_resp = crate::daemon::protocol::DaemonResponse::error(
                "unknown".to_string(),
                "protocol",
                format!("request too large: {} bytes (max {})", n, MAX_REQUEST_SIZE),
            );
            let mut resp_json =
                serde_json::to_string(&error_resp).unwrap_or_else(|_| String::new());
            resp_json.push('\n');
            writer.write_all(resp_json.as_bytes()).await?;
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: DaemonRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let error_resp = crate::daemon::protocol::DaemonResponse::error(
                    "unknown".to_string(),
                    "protocol",
                    format!("invalid request JSON: {}", e),
                );
                let mut resp_json =
                    serde_json::to_string(&error_resp).unwrap_or_else(|_| String::new());
                resp_json.push('\n');
                writer.write_all(resp_json.as_bytes()).await?;
                continue;
            }
        };

        let response = handler.handle(request).await;
        let mut resp_json = serde_json::to_string(&response).unwrap_or_else(|_| String::new());
        resp_json.push('\n');
        writer.write_all(resp_json.as_bytes()).await?;
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

fn dirs_config_path() -> std::path::PathBuf {
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        return std::path::PathBuf::from(config_home)
            .join("falcon-cli")
            .join("daemon.toml");
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home)
            .join(".config")
            .join("falcon-cli")
            .join("daemon.toml");
    }
    std::path::PathBuf::from("/etc/falcon-cli/daemon.toml")
}
