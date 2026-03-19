pub mod client;
pub mod handler;
pub mod peer_verify;
pub mod protocol;
pub mod security;
pub mod server;
pub mod session;

use std::path::PathBuf;
use uuid::Uuid;

/// Default socket directory name.
const SOCKET_DIR: &str = "falcon-cli";

/// Resolve the socket path for an existing agent (from env var or explicit path).
/// Used by clients connecting to a running agent.
pub fn resolve_socket_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }

    // Fallback: find the first existing socket in the socket directory.
    let sockets = list_agent_sockets();
    if sockets.len() == 1 {
        return sockets.into_iter().next().unwrap();
    }

    // Multiple or no sockets: fall back to default name.
    resolve_socket_dir().join("falcon.sock")
}

/// Generate a unique socket path for a new agent instance.
/// Includes the agent PID to avoid collisions when multiple agents run.
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

/// Generate a cryptographically random session token for agent authentication.
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

/// Environment variable names that the agent process needs to retain.
/// All other environment variables are removed after fork to prevent
/// leaking secrets (e.g., tokens loaded by `op run --env-file=.env`).
const ENV_WHITELIST: &[&str] = &[
    // Path resolution
    "HOME",
    "PATH",
    "USER",
    "TMPDIR",
    // XDG directories (session file, config, socket)
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
    // HTTP proxy (reqwest)
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    // TLS certificates
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    // Locale
    "LANG",
    // Debug
    "RUST_LOG",
    "RUST_BACKTRACE",
];

/// Prefix patterns for whitelisted environment variables.
/// Variables whose name starts with any of these prefixes are retained.
const ENV_WHITELIST_PREFIXES: &[&str] = &[
    "LC_", // locale categories (LC_ALL, LC_CTYPE, etc.)
];

/// Remove all environment variables except those in the whitelist.
/// Called after fork() (or in foreground mode after Config is built)
/// to prevent leaking secrets from the parent process environment.
///
/// See ADR-0004 for the design rationale.
pub fn sanitize_env() {
    let vars_to_remove: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| !is_env_whitelisted(k))
        .collect();

    let count = vars_to_remove.len();
    for key in &vars_to_remove {
        // SAFETY: remove_var modifies the libc environ pointer.
        // This is safe because we are single-threaded at this point
        // (called before tokio runtime creation).
        unsafe {
            std::env::remove_var(key);
        }
    }

    if count > 0 {
        eprintln!("agent: sanitized environment ({} variables removed)", count);
    }
}

/// Check if an environment variable name is in the whitelist.
fn is_env_whitelisted(name: &str) -> bool {
    if ENV_WHITELIST.contains(&name) {
        return true;
    }
    for prefix in ENV_WHITELIST_PREFIXES {
        if name.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Apply OS-level process hardening to prevent credential leakage.
///
/// - Linux: `prctl(PR_SET_DUMPABLE, 0)` restricts `/proc/[pid]/environ` access.
/// - macOS: `ptrace(PT_DENY_ATTACH)` prevents debugger attachment.
/// - Both: `setrlimit(RLIMIT_CORE, 0)` disables core dumps.
///
/// Errors are logged but not fatal (e.g., restricted container environments).
pub fn harden_process() {
    harden_process_os();
    disable_core_dump();
}

#[cfg(target_os = "linux")]
fn harden_process_os() {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) is safe; it only affects the calling process.
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if ret != 0 {
        eprintln!(
            "agent: prctl(PR_SET_DUMPABLE, 0) failed: {}",
            std::io::Error::last_os_error()
        );
    } else {
        eprintln!("agent: process hardened (PR_SET_DUMPABLE=0)");
    }
}

#[cfg(target_os = "macos")]
fn harden_process_os() {
    // SAFETY: ptrace(PT_DENY_ATTACH) is safe; it only affects the calling process.
    let ret = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if ret != 0 {
        eprintln!(
            "agent: ptrace(PT_DENY_ATTACH) failed: {}",
            std::io::Error::last_os_error()
        );
    } else {
        eprintln!("agent: process hardened (PT_DENY_ATTACH)");
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn harden_process_os() {
    // No OS-specific hardening available.
}

fn disable_core_dump() {
    // SAFETY: setrlimit is safe; it only affects the calling process.
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rl) };
    if ret != 0 {
        eprintln!(
            "agent: setrlimit(RLIMIT_CORE, 0) failed: {}",
            std::io::Error::last_os_error()
        );
    } else {
        eprintln!("agent: core dumps disabled");
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    #[test]
    fn test_is_env_whitelisted_exact_match() {
        assert!(is_env_whitelisted("HOME"));
        assert!(is_env_whitelisted("PATH"));
        assert!(is_env_whitelisted("RUST_LOG"));
        assert!(is_env_whitelisted("SSL_CERT_FILE"));
        assert!(is_env_whitelisted("http_proxy"));
    }

    #[test]
    fn test_is_env_whitelisted_prefix_match() {
        assert!(is_env_whitelisted("LC_ALL"));
        assert!(is_env_whitelisted("LC_CTYPE"));
        assert!(is_env_whitelisted("LC_MESSAGES"));
    }

    #[test]
    fn test_is_env_whitelisted_rejects_secrets() {
        assert!(!is_env_whitelisted("FALCON_CLIENT_ID"));
        assert!(!is_env_whitelisted("FALCON_CLIENT_SECRET"));
        assert!(!is_env_whitelisted("GITHUB_TOKEN"));
        assert!(!is_env_whitelisted("SLACK_BOT_TOKEN"));
        assert!(!is_env_whitelisted("AWS_SECRET_ACCESS_KEY"));
        assert!(!is_env_whitelisted("DATABASE_URL"));
    }

    #[test]
    fn test_sanitize_env_removes_non_whitelisted() {
        // Set a test variable that is not in the whitelist.
        let key = "FALCON_TEST_SANITIZE_SECRET_12345";
        unsafe {
            std::env::set_var(key, "should-be-removed");
        }
        assert!(std::env::var(key).is_ok());

        sanitize_env();

        assert!(
            std::env::var(key).is_err(),
            "non-whitelisted variable should be removed"
        );
    }

    #[test]
    fn test_sanitize_env_keeps_whitelisted() {
        // HOME should survive sanitization.
        if std::env::var("HOME").is_ok() {
            sanitize_env();
            assert!(
                std::env::var("HOME").is_ok(),
                "HOME should be retained after sanitize_env"
            );
        }
    }
}

/// List all running agent socket paths in the socket directory.
pub fn list_agent_sockets() -> Vec<PathBuf> {
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
