use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Security configuration loaded from a TOML file.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(default)]
    pub security: SecuritySection,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecuritySection {
    /// List of allowed "command:action" pairs. ["*"] means allow all.
    #[serde(default = "default_allowed_commands")]
    pub allowed_commands: Vec<String>,
    /// Maximum requests per minute.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            allowed_commands: default_allowed_commands(),
            rate_limit_per_minute: default_rate_limit(),
        }
    }
}

fn default_allowed_commands() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_rate_limit() -> u32 {
    60
}

impl SecurityConfig {
    /// Load from a TOML file. Returns default if the file does not exist.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).unwrap_or_else(|e| {
                eprintln!(
                    "warning: failed to parse daemon config {}: {}",
                    path.display(),
                    e
                );
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }
}

/// Command whitelist checker.
pub struct CommandWhitelist {
    allow_all: bool,
    allowed: HashSet<String>,
}

impl CommandWhitelist {
    pub fn new(allowed_commands: &[String]) -> Self {
        let allow_all = allowed_commands.iter().any(|c| c == "*");
        let allowed: HashSet<String> = allowed_commands.iter().cloned().collect();
        Self { allow_all, allowed }
    }

    /// Check if a command:action pair is allowed.
    pub fn is_allowed(&self, command: &str, action: &str) -> bool {
        if self.allow_all {
            return true;
        }
        let key = format!("{}:{}", command, action);
        self.allowed.contains(&key)
    }
}

/// Simple token bucket rate limiter.
pub struct RateLimiter {
    max_tokens: u32,
    tokens: Mutex<f64>,
    last_refill: Mutex<Instant>,
    refill_rate: f64, // tokens per second
    total_requests: AtomicU64,
    denied_requests: AtomicU64,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            max_tokens: requests_per_minute,
            tokens: Mutex::new(requests_per_minute as f64),
            last_refill: Mutex::new(Instant::now()),
            refill_rate: requests_per_minute as f64 / 60.0,
            total_requests: AtomicU64::new(0),
            denied_requests: AtomicU64::new(0),
        }
    }

    /// Try to consume one token. Returns true if the request is allowed.
    pub fn try_acquire(&self) -> bool {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut tokens = self.tokens.lock().unwrap();
        let mut last_refill = self.last_refill.lock().unwrap();

        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        *tokens = (*tokens + elapsed * self.refill_rate).min(self.max_tokens as f64);
        *last_refill = now;

        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            self.denied_requests.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    #[cfg(test)]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn denied_requests(&self) -> u64 {
        self.denied_requests.load(Ordering::Relaxed)
    }
}

/// Audit logger that writes to stderr or a file.
pub struct AuditLog;

impl AuditLog {
    /// Log a request received event.
    pub fn log_request(command: &str, action: &str, request_id: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        eprintln!(
            "[audit] {} request={} command={} action={}",
            now, request_id, command, action,
        );
    }

    /// Log a response sent event.
    pub fn log_response(request_id: &str, status: &str, duration_ms: u128) {
        let now = chrono::Utc::now().to_rfc3339();
        eprintln!(
            "[audit] {} request={} status={} duration_ms={}",
            now, request_id, status, duration_ms,
        );
    }

    /// Log a denied request.
    pub fn log_denied(request_id: &str, reason: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        eprintln!(
            "[audit] {} request={} denied reason={}",
            now, request_id, reason,
        );
    }
}

/// Verify that the connecting peer has the same UID as the daemon process.
#[cfg(unix)]
pub fn verify_peer_uid(peer_cred: Option<u32>) -> bool {
    match peer_cred {
        Some(uid) => uid == unsafe { libc::getuid() },
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist_allow_all() {
        let wl = CommandWhitelist::new(&["*".to_string()]);
        assert!(wl.is_allowed("alert", "list"));
        assert!(wl.is_allowed("host", "get"));
    }

    #[test]
    fn test_whitelist_specific() {
        let wl = CommandWhitelist::new(&["alert:list".to_string(), "host:get".to_string()]);
        assert!(wl.is_allowed("alert", "list"));
        assert!(wl.is_allowed("host", "get"));
        assert!(!wl.is_allowed("alert", "get"));
        assert!(!wl.is_allowed("incident", "list"));
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(10);
        for _ in 0..10 {
            assert!(limiter.try_acquire());
        }
    }

    #[test]
    fn test_rate_limiter_denies_over_limit() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
        assert_eq!(limiter.denied_requests(), 1);
    }

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert_eq!(config.security.allowed_commands, vec!["*"]);
        assert_eq!(config.security.rate_limit_per_minute, 60);
    }
}
