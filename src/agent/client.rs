use crate::agent::protocol::{AgentRequest, AgentResponse, AgentStatus};
use crate::error::{FalconError, Result};
use std::collections::HashMap;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};

/// Default timeout for agent requests (30 seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Send a command to the agent and return the response.
pub async fn send_command(
    socket_path: &Path,
    token: String,
    command: String,
    action: String,
    args: HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value> {
    let stream = connect(socket_path).await?;

    let request = AgentRequest::new(token, command, action, args);
    let response = send_request(stream, &request).await?;

    match response.status.as_str() {
        "ok" => Ok(response.data.unwrap_or(serde_json::Value::Null)),
        _ => {
            let detail = response
                .error
                .unwrap_or(crate::agent::protocol::ErrorDetail {
                    kind: "unknown".to_string(),
                    message: "unknown error".to_string(),
                });
            Err(FalconError::Api(format!(
                "[{}] {}",
                detail.kind, detail.message
            )))
        }
    }
}

/// Check the agent status via session.json.
pub async fn status() -> AgentStatus {
    let session_path = crate::agent::session::session_file_path();
    match crate::agent::session::read_session() {
        Some(session) => {
            let socket_path = std::path::PathBuf::from(&session.socket_path);
            let running = check_running(&socket_path).await;
            AgentStatus {
                running,
                pid: Some(session.pid),
                socket_path: session.socket_path,
                uptime_seconds: None,
                session_file: Some(session_path.display().to_string()),
            }
        }
        None => AgentStatus {
            running: false,
            pid: None,
            socket_path: String::new(),
            uptime_seconds: None,
            session_file: Some(session_path.display().to_string()),
        },
    }
}

/// Stop the agent using session.json to find the PID and socket path.
///
/// Unlike `stop()`, this uses the PID stored in session.json directly,
/// avoiding the need to read a separate PID file.
pub fn stop_from_session() -> Result<()> {
    let session = crate::agent::session::read_session().ok_or_else(|| {
        FalconError::Config("agent is not running (no session file found)".to_string())
    })?;
    let socket_path = std::path::PathBuf::from(&session.socket_path);
    let pid = session.pid as i32;

    send_sigterm(pid)?;
    cleanup_pid_file(&socket_path);
    cleanup_session_file(&socket_path);

    eprintln!("sent SIGTERM to agent (PID {})", pid);
    Ok(())
}

/// Stop the agent by reading the PID file and sending SIGTERM.
///
/// Used when stopping by socket path (e.g., `--socket` or `--all`).
pub fn stop(socket_path: &Path) -> Result<()> {
    let pid_path = crate::agent::resolve_pid_path(socket_path);
    let pid = std::fs::read_to_string(&pid_path)
        .map_err(|e| {
            FalconError::Config(format!(
                "failed to read PID file {}: {} (is the agent running?)",
                pid_path.display(),
                e
            ))
        })?
        .trim()
        .parse::<i32>()
        .map_err(|e| {
            FalconError::Config(format!("invalid PID in {}: {}", pid_path.display(), e))
        })?;

    send_sigterm(pid)?;
    cleanup_pid_file(socket_path);
    cleanup_session_file(socket_path);

    eprintln!("sent SIGTERM to agent (PID {})", pid);
    Ok(())
}

/// Send SIGTERM to the given PID.
///
/// Rejects non-positive PIDs to prevent sending signals to process groups
/// (pid == 0 targets the caller's group, pid == -1 targets all processes).
fn send_sigterm(pid: i32) -> Result<()> {
    if pid <= 0 {
        return Err(FalconError::Config(format!(
            "invalid PID {}: must be a positive integer",
            pid
        )));
    }

    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(FalconError::Config(format!(
                "failed to send SIGTERM to PID {}: {}",
                pid, err
            )));
        }
    }
    Ok(())
}

/// Remove the PID file associated with the socket path.
fn cleanup_pid_file(socket_path: &Path) {
    let pid_path = crate::agent::resolve_pid_path(socket_path);
    let _ = std::fs::remove_file(&pid_path);
}

/// Stop all running agent instances.
pub fn stop_all() -> Result<()> {
    let sockets = crate::agent::list_agent_sockets();
    if sockets.is_empty() {
        eprintln!("no running agents found");
        return Ok(());
    }

    let mut errors = 0;
    for socket_path in &sockets {
        match stop(socket_path) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("failed to stop agent at {}: {}", socket_path.display(), e);
                errors += 1;
            }
        }
    }

    if errors > 0 {
        Err(FalconError::Config(format!(
            "failed to stop {} of {} agents",
            errors,
            sockets.len()
        )))
    } else {
        eprintln!("stopped {} agent(s)", sockets.len());
        Ok(())
    }
}

/// Remove session file if it references the given socket path.
fn cleanup_session_file(socket_path: &Path) {
    if let Some(session) = crate::agent::session::read_session() {
        if session.socket_path == socket_path.display().to_string() {
            crate::agent::session::remove_session();
            eprintln!("removed session file");
        }
    }
}

async fn connect(socket_path: &Path) -> Result<UnixStream> {
    let stream = timeout(Duration::from_secs(5), UnixStream::connect(socket_path))
        .await
        .map_err(|_| FalconError::Config("connection to agent timed out".to_string()))?
        .map_err(|e| {
            FalconError::Config(format!(
                "failed to connect to agent at {}: {} (is the agent running?)",
                socket_path.display(),
                e
            ))
        })?;

    Ok(stream)
}

async fn send_request(stream: UnixStream, request: &AgentRequest) -> Result<AgentResponse> {
    let (reader, mut writer) = stream.into_split();

    let mut req_json = serde_json::to_string(request)?;
    req_json.push('\n');
    writer
        .write_all(req_json.as_bytes())
        .await
        .map_err(|e| FalconError::Config(format!("failed to send request to agent: {}", e)))?;

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    let n = timeout(
        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        buf_reader.read_line(&mut line),
    )
    .await
    .map_err(|_| FalconError::Config("agent request timed out".to_string()))?
    .map_err(|e| FalconError::Config(format!("failed to read agent response: {}", e)))?;

    if n == 0 {
        return Err(FalconError::Config(
            "agent closed connection without response".to_string(),
        ));
    }

    let response: AgentResponse = serde_json::from_str(line.trim())?;
    Ok(response)
}

pub async fn check_running(socket_path: &Path) -> bool {
    connect(socket_path).await.is_ok()
}
