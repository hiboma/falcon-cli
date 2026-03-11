pub mod client;
pub mod handler;
pub mod peer_verify;
pub mod protocol;
pub mod security;
pub mod server;

use std::path::PathBuf;
use uuid::Uuid;

/// Default socket directory name.
const SOCKET_DIR: &str = "falcon-cli";

/// Resolve the socket path for an existing daemon (from env var or explicit path).
/// Used by clients connecting to a running daemon.
pub fn resolve_socket_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }

    // Fallback for daemon status/stop without FALCON_DAEMON_SOCKET set.
    resolve_socket_dir().join("falcon.sock")
}

/// Generate a unique socket path for a new daemon instance.
/// Includes the daemon PID to avoid collisions when multiple daemons run.
pub fn generate_socket_path() -> PathBuf {
    let pid = std::process::id();
    resolve_socket_dir().join(format!("falcon-{}.sock", pid))
}

/// Resolve the socket directory.
fn resolve_socket_dir() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join(SOCKET_DIR);
    }

    // SAFETY: getuid() is always safe with no side effects.
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/{}-{}", SOCKET_DIR, uid))
}

/// Generate a cryptographically random session token for daemon authentication.
pub fn generate_token() -> String {
    // Concatenate two UUIDv4 to get a 256-bit token.
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Resolve the PID file path from a socket path.
/// e.g., falcon-12345.sock -> falcon-12345.pid
pub fn resolve_pid_path(socket_path: &std::path::Path) -> PathBuf {
    let stem = socket_path
        .file_stem()
        .unwrap_or(std::ffi::OsStr::new("falcon"));
    socket_path
        .parent()
        .unwrap_or(std::path::Path::new("/tmp"))
        .join(format!("{}.pid", stem.to_string_lossy()))
}

/// List all running daemon socket paths in the socket directory.
pub fn list_daemon_sockets() -> Vec<PathBuf> {
    let dir = resolve_socket_dir();
    let mut sockets = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sock") {
                sockets.push(path);
            }
        }
    }
    sockets
}
