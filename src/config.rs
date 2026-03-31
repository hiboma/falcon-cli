use serde::Deserialize;
use std::path::PathBuf;

use crate::error::{FalconError, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub base_url: String,
    pub member_cid: Option<String>,
}

/// TOML representation of `[credentials]` in credentials.toml.
#[derive(Debug, Deserialize, Default)]
struct CredentialsFileRoot {
    #[serde(default)]
    credentials: CredentialsFile,
}

#[derive(Debug, Deserialize, Default)]
struct CredentialsFile {
    client_id: Option<String>,
    client_secret: Option<String>,
    base_url: Option<String>,
    member_cid: Option<String>,
}

/// Resolved Falcon API credentials collected from CLI args, environment variables,
/// and credentials.toml.
/// Once constructed, the process should call `FalconCredentials::clear_env()` to remove
/// credential environment variables so that forked child processes do not inherit them.
#[derive(Debug, Clone, Default)]
pub struct FalconCredentials {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub base_url: String,
    pub member_cid: Option<String>,
}

/// Search paths for credentials.toml (highest priority first).
fn credentials_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(".falcon-credentials.toml")];
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        paths.push(
            PathBuf::from(config_home)
                .join("falcon-cli")
                .join("credentials.toml"),
        );
    } else if let Ok(home) = std::env::var("HOME") {
        paths.push(
            PathBuf::from(home)
                .join(".config")
                .join("falcon-cli")
                .join("credentials.toml"),
        );
    }
    paths
}

/// Load credentials from the first credentials.toml found.
fn load_credentials_file() -> CredentialsFile {
    for path in credentials_search_paths() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(root) = toml::from_str::<CredentialsFileRoot>(&content) {
                return root.credentials;
            }
        }
    }
    CredentialsFile::default()
}

impl FalconCredentials {
    /// Resolve credentials from CLI args, environment variables, and credentials.toml.
    /// Priority: CLI args > environment variables > credentials.toml > defaults.
    pub fn resolve(
        cli_client_id: Option<&str>,
        cli_base_url: Option<&str>,
        cli_member_cid: Option<&str>,
    ) -> Self {
        let file = load_credentials_file();

        let client_id = cli_client_id
            .map(String::from)
            .or_else(|| std::env::var("FALCON_CLIENT_ID").ok())
            .or(file.client_id);

        let client_secret = std::env::var("FALCON_CLIENT_SECRET")
            .ok()
            .or(file.client_secret);

        let base_url = cli_base_url
            .map(String::from)
            .or_else(|| std::env::var("FALCON_BASE_URL").ok())
            .or(file.base_url)
            .unwrap_or_else(|| "https://api.crowdstrike.com".to_string());

        let member_cid = cli_member_cid
            .map(String::from)
            .or_else(|| std::env::var("FALCON_MEMBER_CID").ok())
            .or(file.member_cid);

        Self {
            client_id,
            client_secret,
            base_url,
            member_cid,
        }
    }

    /// Validate that required credentials are present for API access.
    pub fn validate(&self) -> std::result::Result<(), String> {
        let mut missing = Vec::new();
        if self.client_id.is_none() {
            missing.push("FALCON_CLIENT_ID");
        }
        if self.client_secret.is_none() {
            missing.push("FALCON_CLIENT_SECRET");
        }

        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "missing required credentials: {}. Set via environment variables or CLI args.",
                missing.join(", ")
            ))
        }
    }

    /// Build a `Config` from the resolved credentials.
    /// Returns an error if required fields are missing.
    pub fn to_config(&self) -> Result<Config> {
        let client_id = self.client_id.clone().ok_or_else(|| {
            FalconError::Config(
                "client_id not set. Use --client-id or FALCON_CLIENT_ID.".to_string(),
            )
        })?;
        let client_secret = self.client_secret.clone().ok_or_else(|| {
            FalconError::Config(
                "client_secret not set. Set FALCON_CLIENT_SECRET env var.".to_string(),
            )
        })?;

        Ok(Config {
            client_id,
            client_secret,
            base_url: self.base_url.clone(),
            member_cid: self.member_cid.clone(),
        })
    }

    /// Remove Falcon credential environment variables from the current process.
    /// First overwrites the values in-place (via the C `environ` pointer) so that
    /// the kernel's process environment snapshot — visible through `ps -E` or
    /// `/proc/<pid>/environ` — no longer contains the real secrets.
    /// Then calls `remove_var` to fully unset each variable.
    ///
    /// # Safety
    /// Must be called in a single-threaded context (before tokio runtime creation).
    pub unsafe fn clear_env() {
        for key in &[
            "FALCON_CLIENT_ID",
            "FALCON_CLIENT_SECRET",
            "FALCON_BASE_URL",
            "FALCON_MEMBER_CID",
        ] {
            unsafe {
                overwrite_environ_value(key);
                std::env::remove_var(key);
            }
        }
    }
}

/// Overwrite the value portion of an environment variable in-place with `*`.
/// This mutates the C `environ` array directly so that the kernel's snapshot
/// (read by `ps -E` / `/proc/<pid>/environ`) is scrubbed.
///
/// # Safety
/// Must be called in a single-threaded context. The `environ` pointer and its
/// strings must not be concurrently accessed.
unsafe fn overwrite_environ_value(name: &str) {
    unsafe extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }

    unsafe {
        if environ.is_null() {
            return;
        }

        let name_bytes = name.as_bytes();
        let mut ep = environ;
        while !(*ep).is_null() {
            let entry = *ep;
            // Check if entry starts with "NAME="
            let mut matches = true;
            for (i, &b) in name_bytes.iter().enumerate() {
                if *entry.add(i) as u8 != b {
                    matches = false;
                    break;
                }
            }
            if matches && *entry.add(name_bytes.len()) == b'=' as libc::c_char {
                // Overwrite the value portion with '*'
                let val_start = entry.add(name_bytes.len() + 1);
                let mut p = val_start;
                while *p != 0 {
                    *p = b'*' as libc::c_char;
                    p = p.add(1);
                }
                return;
            }
            ep = ep.add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon_credentials_validate_ok() {
        let creds = FalconCredentials {
            client_id: Some("id".to_string()),
            client_secret: Some("secret".to_string()),
            ..Default::default()
        };
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn test_falcon_credentials_validate_missing() {
        let creds = FalconCredentials::default();
        let err = creds.validate().unwrap_err();
        assert!(err.contains("FALCON_CLIENT_ID"));
        assert!(err.contains("FALCON_CLIENT_SECRET"));
    }

    #[test]
    fn test_falcon_credentials_validate_partial_missing() {
        let creds = FalconCredentials {
            client_id: Some("id".to_string()),
            ..Default::default()
        };
        let err = creds.validate().unwrap_err();
        assert!(!err.contains("FALCON_CLIENT_ID"));
        assert!(err.contains("FALCON_CLIENT_SECRET"));
    }

    #[test]
    fn test_falcon_credentials_to_config() {
        let creds = FalconCredentials {
            client_id: Some("id".to_string()),
            client_secret: Some("secret".to_string()),
            base_url: "https://example.com".to_string(),
            member_cid: Some("cid".to_string()),
        };
        let config = creds.to_config().unwrap();
        assert_eq!(config.client_id, "id");
        assert_eq!(config.client_secret, "secret");
        assert_eq!(config.base_url, "https://example.com");
        assert_eq!(config.member_cid.as_deref(), Some("cid"));
    }

    #[test]
    fn test_falcon_credentials_to_config_missing() {
        let creds = FalconCredentials::default();
        assert!(creds.to_config().is_err());
    }

    /// Helper to ensure FALCON_* env vars are cleared before tests that call resolve().
    unsafe fn clear_falcon_env() {
        unsafe {
            std::env::remove_var("FALCON_CLIENT_ID");
            std::env::remove_var("FALCON_CLIENT_SECRET");
            std::env::remove_var("FALCON_BASE_URL");
            std::env::remove_var("FALCON_MEMBER_CID");
        }
    }

    #[test]
    fn test_falcon_credentials_resolve_cli_overrides_env() {
        unsafe { clear_falcon_env() };
        unsafe {
            std::env::set_var("FALCON_CLIENT_ID", "env-id");
        }
        let creds = FalconCredentials::resolve(Some("cli-id"), None, None);
        assert_eq!(creds.client_id.as_deref(), Some("cli-id"));
        unsafe { clear_falcon_env() };
    }

    #[test]
    fn test_falcon_credentials_resolve_env_fallback() {
        unsafe { clear_falcon_env() };
        unsafe {
            std::env::set_var("FALCON_CLIENT_ID", "env-id");
            std::env::set_var("FALCON_CLIENT_SECRET", "env-secret");
        }
        let creds = FalconCredentials::resolve(None, None, None);
        assert_eq!(creds.client_id.as_deref(), Some("env-id"));
        assert_eq!(creds.client_secret.as_deref(), Some("env-secret"));
        unsafe { clear_falcon_env() };
    }

    #[test]
    fn test_falcon_credentials_resolve_default_base_url() {
        unsafe { clear_falcon_env() };
        let creds = FalconCredentials::resolve(None, None, None);
        assert_eq!(creds.base_url, "https://api.crowdstrike.com");
    }

    #[test]
    fn test_falcon_credentials_resolve_empty() {
        unsafe { clear_falcon_env() };
        let creds = FalconCredentials::resolve(None, None, None);
        assert!(creds.client_id.is_none());
        assert!(creds.client_secret.is_none());
        assert!(creds.member_cid.is_none());
    }

    #[test]
    fn test_falcon_credentials_clear_env() {
        unsafe {
            std::env::set_var("FALCON_CLIENT_ID", "test-id");
            std::env::set_var("FALCON_CLIENT_SECRET", "test-secret");
            std::env::set_var("FALCON_BASE_URL", "https://example.com");
            std::env::set_var("FALCON_MEMBER_CID", "test-cid");
        }

        unsafe {
            FalconCredentials::clear_env();
        }

        assert!(std::env::var("FALCON_CLIENT_ID").is_err());
        assert!(std::env::var("FALCON_CLIENT_SECRET").is_err());
        assert!(std::env::var("FALCON_BASE_URL").is_err());
        assert!(std::env::var("FALCON_MEMBER_CID").is_err());
    }

    #[test]
    fn test_credentials_file_parse_full() {
        let toml_str = r#"
[credentials]
client_id = "toml-id"
client_secret = "toml-secret"
base_url = "https://api.eu-1.crowdstrike.com"
member_cid = "toml-cid"
"#;
        let root: CredentialsFileRoot = toml::from_str(toml_str).unwrap();
        assert_eq!(root.credentials.client_id.as_deref(), Some("toml-id"));
        assert_eq!(
            root.credentials.client_secret.as_deref(),
            Some("toml-secret")
        );
        assert_eq!(
            root.credentials.base_url.as_deref(),
            Some("https://api.eu-1.crowdstrike.com")
        );
        assert_eq!(root.credentials.member_cid.as_deref(), Some("toml-cid"));
    }

    #[test]
    fn test_credentials_file_parse_minimal() {
        let toml_str = r#"
[credentials]
client_id = "toml-id"
client_secret = "toml-secret"
"#;
        let root: CredentialsFileRoot = toml::from_str(toml_str).unwrap();
        assert_eq!(root.credentials.client_id.as_deref(), Some("toml-id"));
        assert!(root.credentials.base_url.is_none());
        assert!(root.credentials.member_cid.is_none());
    }

    #[test]
    fn test_credentials_file_parse_empty() {
        let toml_str = "";
        let root: CredentialsFileRoot = toml::from_str(toml_str).unwrap();
        assert!(root.credentials.client_id.is_none());
        assert!(root.credentials.client_secret.is_none());
    }

    #[test]
    fn test_credentials_file_empty_values_ignored() {
        let toml_str = r#"
[credentials]
client_id = ""
client_secret = ""
"#;
        let root: CredentialsFileRoot = toml::from_str(toml_str).unwrap();
        // Empty strings are parsed as Some(""), not None
        assert_eq!(root.credentials.client_id.as_deref(), Some(""));
    }

    #[test]
    fn test_falcon_credentials_resolve_then_clear_env() {
        unsafe {
            std::env::set_var("FALCON_CLIENT_ID", "env-id");
            std::env::set_var("FALCON_CLIENT_SECRET", "env-secret");
        }

        let creds = FalconCredentials::resolve(None, None, None);
        assert_eq!(creds.client_id.as_deref(), Some("env-id"));
        assert_eq!(creds.client_secret.as_deref(), Some("env-secret"));

        unsafe {
            FalconCredentials::clear_env();
        }

        // Credentials struct still holds the values.
        assert_eq!(creds.client_id.as_deref(), Some("env-id"));
        assert_eq!(creds.client_secret.as_deref(), Some("env-secret"));

        // But env vars are gone.
        assert!(std::env::var("FALCON_CLIENT_ID").is_err());
        assert!(std::env::var("FALCON_CLIENT_SECRET").is_err());
    }
}
