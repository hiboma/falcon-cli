use crate::daemon::protocol::{DaemonRequest, DaemonResponse, DaemonStatus};
use crate::error::{FalconError, Result};
use std::collections::HashMap;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};

/// Default timeout for daemon requests (30 seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Send a command to the daemon and return the response.
pub async fn send_command(
    socket_path: &Path,
    token: String,
    command: String,
    action: String,
    args: HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value> {
    let stream = connect(socket_path).await?;

    let request = DaemonRequest::new(token, command, action, args);
    let response = send_request(stream, &request).await?;

    match response.status.as_str() {
        "ok" => Ok(response.data.unwrap_or(serde_json::Value::Null)),
        _ => {
            let detail = response
                .error
                .unwrap_or(crate::daemon::protocol::ErrorDetail {
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

/// Check the status of the daemon.
pub async fn status(socket_path: &Path) -> DaemonStatus {
    let pid = read_pid(socket_path);
    let running = check_running(socket_path).await;

    DaemonStatus {
        running,
        pid,
        socket_path: socket_path.display().to_string(),
        uptime_seconds: None,
    }
}

/// Stop the daemon by sending SIGTERM to the PID.
pub fn stop(socket_path: &Path) -> Result<()> {
    let pid_path = crate::daemon::resolve_pid_path(socket_path);
    let pid = std::fs::read_to_string(&pid_path)
        .map_err(|e| FalconError::Config(format!("failed to read PID file: {}", e)))?
        .trim()
        .parse::<i32>()
        .map_err(|e| FalconError::Config(format!("invalid PID: {}", e)))?;

    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
        if ret != 0 {
            return Err(FalconError::Config(format!(
                "failed to send SIGTERM to PID {}",
                pid
            )));
        }
    }

    eprintln!("sent SIGTERM to daemon (PID {})", pid);
    Ok(())
}

/// Stop all running daemon instances.
pub fn stop_all() -> Result<()> {
    let sockets = crate::daemon::list_daemon_sockets();
    if sockets.is_empty() {
        eprintln!("no running daemons found");
        return Ok(());
    }

    let mut errors = 0;
    for socket_path in &sockets {
        match stop(socket_path) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("failed to stop daemon at {}: {}", socket_path.display(), e);
                errors += 1;
            }
        }
    }

    if errors > 0 {
        Err(FalconError::Config(format!(
            "failed to stop {} of {} daemons",
            errors,
            sockets.len()
        )))
    } else {
        eprintln!("stopped {} daemon(s)", sockets.len());
        Ok(())
    }
}

async fn connect(socket_path: &Path) -> Result<UnixStream> {
    let stream = timeout(Duration::from_secs(5), UnixStream::connect(socket_path))
        .await
        .map_err(|_| FalconError::Config("connection to daemon timed out".to_string()))?
        .map_err(|e| {
            FalconError::Config(format!(
                "failed to connect to daemon at {}: {} (is the daemon running?)",
                socket_path.display(),
                e
            ))
        })?;

    Ok(stream)
}

async fn send_request(stream: UnixStream, request: &DaemonRequest) -> Result<DaemonResponse> {
    let (reader, mut writer) = stream.into_split();

    let mut req_json = serde_json::to_string(request)?;
    req_json.push('\n');
    writer
        .write_all(req_json.as_bytes())
        .await
        .map_err(|e| FalconError::Config(format!("failed to send request to daemon: {}", e)))?;

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    let n = timeout(
        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        buf_reader.read_line(&mut line),
    )
    .await
    .map_err(|_| FalconError::Config("daemon request timed out".to_string()))?
    .map_err(|e| FalconError::Config(format!("failed to read daemon response: {}", e)))?;

    if n == 0 {
        return Err(FalconError::Config(
            "daemon closed connection without response".to_string(),
        ));
    }

    let response: DaemonResponse = serde_json::from_str(line.trim())?;
    Ok(response)
}

async fn check_running(socket_path: &Path) -> bool {
    connect(socket_path).await.is_ok()
}

fn read_pid(socket_path: &Path) -> Option<u32> {
    let pid_path = crate::daemon::resolve_pid_path(socket_path);
    std::fs::read_to_string(&pid_path).ok()?.trim().parse().ok()
}
