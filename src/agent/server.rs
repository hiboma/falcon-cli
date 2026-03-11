use crate::agent::handler::RequestHandler;
use crate::agent::protocol::AgentRequest;
use crate::agent::security::{CommandWhitelist, RateLimiter, SecurityConfig};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;

use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum size of a single request line (1 MiB).
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

/// Maximum number of concurrent connections.
const MAX_CONNECTIONS: usize = 64;

/// Idle timeout: auto-shutdown after 8 hours without requests.
const IDLE_TIMEOUT_SECS: u64 = 8 * 60 * 60;

/// Interval to check parent process liveness and idle timeout.
const WATCHDOG_INTERVAL_SECS: u64 = 30;

/// Start the agent server.
///
/// By default, the agent forks into the background (like ssh-agent).
/// The parent process outputs shell variables to stdout and exits.
/// Use `--foreground` to run in the foreground without forking.
pub fn start(
    falcon_client: Arc<crate::client::FalconClient>,
    socket_path: &Path,
    config_path: Option<&Path>,
    foreground: bool,
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

    // Generate session token before fork so the parent can output it.
    let session_token = crate::agent::generate_token();

    if foreground {
        // Run in the foreground (no fork).
        let rt = tokio::runtime::Runtime::new().map_err(|e| {
            crate::error::FalconError::Config(format!("failed to create tokio runtime: {}", e))
        })?;
        // SAFETY: getsid(0) is always safe.
        let session_leader_pid = unsafe { libc::getsid(0) };
        rt.block_on(run_agent(
            falcon_client,
            socket_path,
            whitelist,
            rate_limiter,
            session_token,
            true,
            session_leader_pid,
        ))
    } else {
        // Fork into the background (ssh-agent style).
        fork_into_background(
            falcon_client,
            socket_path,
            whitelist,
            rate_limiter,
            session_token,
        )
    }
}

/// Fork the agent process into the background.
/// The parent outputs SSH Agent-style shell variables and exits.
/// The child runs the agent server.
fn fork_into_background(
    falcon_client: Arc<crate::client::FalconClient>,
    socket_path: &Path,
    whitelist: Arc<CommandWhitelist>,
    rate_limiter: Arc<RateLimiter>,
    session_token: String,
) -> crate::error::Result<()> {
    // Record the session leader PID before fork. Using getsid(0) instead of
    // getppid() so the watchdog monitors the terminal session leader (login
    // shell), not the immediate parent. This prevents premature shutdown when
    // launched indirectly (e.g. via Claude Code's temporary shell).
    // SAFETY: getsid(0) is always safe.
    let session_leader_pid = unsafe { libc::getsid(0) };

    // SAFETY: fork() is safe here because we are single-threaded at this point
    // (tokio runtime has not been created yet).
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => Err(crate::error::FalconError::Config(format!(
            "fork() failed: {}",
            std::io::Error::last_os_error()
        ))),
        0 => {
            // Child process: become session leader and run agent.
            // SAFETY: setsid() is always safe.
            unsafe { libc::setsid() };

            // Generate a unique socket path using the agent PID.
            let actual_socket_path = crate::agent::generate_socket_path();

            // Redirect stdin/stdout to /dev/null, stderr to log file.
            redirect_stdio(&actual_socket_path);

            let rt = tokio::runtime::Runtime::new().map_err(|e| {
                crate::error::FalconError::Config(format!("failed to create tokio runtime: {}", e))
            })?;
            rt.block_on(run_agent(
                falcon_client,
                &actual_socket_path,
                whitelist,
                rate_limiter,
                session_token,
                false,
                session_leader_pid,
            ))
        }
        child_pid => {
            // Parent process: output shell variables and exit.
            // The actual socket path includes the child PID.
            let actual_socket_path = socket_path
                .parent()
                .unwrap_or(Path::new("/tmp"))
                .join(format!("falcon-{}.sock", child_pid));
            println!(
                "FALCON_AGENT_SOCKET={}; export FALCON_AGENT_SOCKET;",
                actual_socket_path.display()
            );
            println!(
                "FALCON_AGENT_TOKEN={}; export FALCON_AGENT_TOKEN;",
                session_token
            );
            println!("FALCON_AGENT_PID={}; export FALCON_AGENT_PID;", child_pid);
            println!("echo agent started, pid {};", child_pid);
            Ok(())
        }
    }
}

/// Redirect stdin and stdout to /dev/null, stderr to a log file.
fn redirect_stdio(socket_path: &Path) {
    // SAFETY: open, dup2, close are safe POSIX system calls.
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::dup2(devnull, libc::STDOUT_FILENO);
            if devnull > libc::STDERR_FILENO {
                libc::close(devnull);
            }
        }

        // Redirect stderr to a log file next to the socket.
        let log_path = socket_path
            .parent()
            .unwrap_or(Path::new("/tmp"))
            .join("falcon-cli.log");
        if let Ok(log_cstr) = std::ffi::CString::new(log_path.to_string_lossy().as_bytes()) {
            let log_fd = libc::open(
                log_cstr.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                0o600,
            );
            if log_fd >= 0 {
                libc::dup2(log_fd, libc::STDERR_FILENO);
                if log_fd > libc::STDERR_FILENO {
                    libc::close(log_fd);
                }
            }
        }
    }
}

/// Run the agent server (binds socket, accepts connections, handles shutdown).
async fn run_agent(
    falcon_client: Arc<crate::client::FalconClient>,
    socket_path: &Path,
    whitelist: Arc<CommandWhitelist>,
    rate_limiter: Arc<RateLimiter>,
    session_token: String,
    print_env: bool,
    session_leader_pid: libc::pid_t,
) -> crate::error::Result<()> {
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
    let pid_path = crate::agent::resolve_pid_path(socket_path);
    std::fs::write(&pid_path, std::process::id().to_string()).map_err(|e| {
        crate::error::FalconError::Config(format!("failed to write PID file: {}", e))
    })?;

    // Tracks the epoch second of the last request for idle timeout.
    let last_activity = Arc::new(AtomicU64::new(epoch_secs()));

    let handler = Arc::new(RequestHandler::new(
        falcon_client,
        whitelist,
        rate_limiter,
        session_token.clone(),
    ));

    if print_env {
        // Foreground mode: output shell variables to stdout.
        println!(
            "FALCON_AGENT_SOCKET={}; export FALCON_AGENT_SOCKET;",
            socket_path.display()
        );
        println!(
            "FALCON_AGENT_TOKEN={}; export FALCON_AGENT_TOKEN;",
            session_token
        );
        println!("echo agent started, pid {};", std::process::id());
    }

    eprintln!("agent: listening on {}", socket_path.display());
    eprintln!("agent: PID {}", std::process::id());
    eprintln!("agent: session leader PID {}", session_leader_pid);

    // Accept loop with graceful shutdown on SIGTERM/SIGINT,
    // parent process exit detection, and idle timeout.
    let socket_path_owned = socket_path.to_owned();
    let pid_path_owned = pid_path.clone();

    tokio::select! {
        _ = accept_loop(&listener, handler, last_activity.clone()) => {}
        _ = shutdown_signal() => {
            eprintln!("agent: shutting down (signal)");
        }
        reason = watchdog(session_leader_pid, last_activity) => {
            eprintln!("agent: shutting down ({})", reason);
        }
    }

    // Cleanup.
    let _ = std::fs::remove_file(&socket_path_owned);
    let _ = std::fs::remove_file(&pid_path_owned);
    eprintln!("agent: stopped");

    Ok(())
}

async fn accept_loop(
    listener: &UnixListener,
    handler: Arc<RequestHandler>,
    last_activity: Arc<AtomicU64>,
) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // Verify peer UID.
                #[cfg(unix)]
                {
                    let peer_uid = stream.peer_cred().ok().map(|cred| cred.uid());
                    if !crate::agent::security::verify_peer_uid(peer_uid) {
                        eprintln!("agent: rejected connection from unauthorized UID");
                        continue;
                    }
                }

                // Verify peer process (code signature on macOS, path match on Linux).
                match crate::agent::peer_verify::verify_peer(&stream) {
                    Ok(verification) => {
                        if !verification.signature_valid {
                            eprintln!(
                                "agent: rejected connection from unverified binary pid={} path={}",
                                verification.pid, verification.exe_path,
                            );
                            continue;
                        }
                        eprintln!(
                            "agent: accepted connection pid={} path={}",
                            verification.pid, verification.exe_path,
                        );
                    }
                    Err(e) => {
                        eprintln!("agent: peer verification failed: {}", e);
                        continue;
                    }
                }

                last_activity.store(epoch_secs(), Ordering::Relaxed);

                let handler = handler.clone();
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("agent: rejected connection, max connections reached");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, handler).await {
                        eprintln!("agent: connection error: {}", e);
                    }
                    drop(permit);
                });
            }
            Err(e) => {
                eprintln!("agent: accept error: {}", e);
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
            let error_resp = crate::agent::protocol::AgentResponse::error(
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

        let request: AgentRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let error_resp = crate::agent::protocol::AgentResponse::error(
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

/// Watchdog task: checks session leader liveness and idle timeout.
/// Returns a reason string when the agent should shut down.
async fn watchdog(session_leader_pid: libc::pid_t, last_activity: Arc<AtomicU64>) -> &'static str {
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(WATCHDOG_INTERVAL_SECS));

    loop {
        interval.tick().await;

        // Check if session leader is still alive.
        // SAFETY: kill(pid, 0) checks process existence without sending a signal.
        let session_alive = unsafe { libc::kill(session_leader_pid, 0) } == 0;
        if !session_alive {
            return "session leader exited";
        }

        // Check idle timeout.
        let last = last_activity.load(Ordering::Relaxed);
        let now = epoch_secs();
        if now.saturating_sub(last) >= IDLE_TIMEOUT_SECS {
            return "idle timeout";
        }
    }
}

/// Get the current time as seconds since UNIX epoch.
fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn dirs_config_path() -> std::path::PathBuf {
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        return std::path::PathBuf::from(config_home)
            .join("falcon-cli")
            .join("agent.toml");
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home)
            .join(".config")
            .join("falcon-cli")
            .join("agent.toml");
    }
    std::path::PathBuf::from("/etc/falcon-cli/agent.toml")
}
