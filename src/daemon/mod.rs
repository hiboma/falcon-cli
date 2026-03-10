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
/// Default socket file name.
const SOCKET_FILE: &str = "falcon.sock";
/// Default PID file name.
const PID_FILE: &str = "falcon-cli.pid";

/// Resolve the socket path.
/// Priority: explicit path > $XDG_RUNTIME_DIR/falcon-cli/falcon.sock > /tmp/falcon-cli-$UID/falcon.sock
pub fn resolve_socket_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }

    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir)
            .join(SOCKET_DIR)
            .join(SOCKET_FILE);
    }

    // SAFETY: getuid() is always safe with no side effects.
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/{}-{}", SOCKET_DIR, uid)).join(SOCKET_FILE)
}

/// Generate a cryptographically random session token for daemon authentication.
pub fn generate_token() -> String {
    // Concatenate two UUIDv4 to get a 256-bit token.
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Resolve the PID file path (same directory as the socket).
pub fn resolve_pid_path(socket_path: &std::path::Path) -> PathBuf {
    socket_path
        .parent()
        .unwrap_or(std::path::Path::new("/tmp"))
        .join(PID_FILE)
}
