use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Top-level profile configuration loaded from `.falcon-cli.toml` or
/// `~/.config/falcon-cli/config.toml`.
#[derive(Debug, Deserialize, Default)]
pub struct ProfileConfig {
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
}

/// A single named profile that controls which commands are visible/allowed.
#[derive(Debug, Deserialize, Clone)]
pub struct Profile {
    #[serde(default)]
    pub description: String,
    pub commands: Vec<String>,
}

/// Resolved profile ready for runtime use.
#[derive(Debug, Clone)]
pub struct ActiveProfile {
    pub name: String,
    pub description: String,
    pub commands: Vec<String>,
}

impl ActiveProfile {
    /// Returns `true` if the given CLI command name is allowed by this profile.
    pub fn is_command_allowed(&self, cmd: &str) -> bool {
        if self.commands.iter().any(|c| c == "*") {
            return true;
        }
        self.commands.iter().any(|c| c == cmd)
    }
}

/// Search paths for the profile configuration file (highest priority first).
fn config_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(".falcon-cli.toml")];
    if let Some(home) = dirs_home() {
        paths.push(home.join(".config/falcon-cli/config.toml"));
    }
    paths
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Load the first profile configuration file found.
pub fn load_config() -> Option<ProfileConfig> {
    for path in config_search_paths() {
        if let Some(config) = load_config_from(&path) {
            return Some(config);
        }
    }
    None
}

/// Load a profile configuration file from a specific path.
fn load_config_from(path: &Path) -> Option<ProfileConfig> {
    let content = std::fs::read_to_string(path).ok()?;
    toml::from_str(&content).ok()
}

/// Resolve the active profile using the priority:
/// 1. `--profile` CLI flag (passed as `cli_profile`)
/// 2. `FALCON_PROFILE` environment variable
/// 3. `default_profile` from config
/// 4. `None` → all commands enabled
pub fn resolve(cli_profile: Option<&str>) -> Option<ActiveProfile> {
    let config = load_config()?;

    // Determine profile name by priority.
    let name = cli_profile
        .map(|s| s.to_string())
        .or_else(|| std::env::var("FALCON_PROFILE").ok())
        .or(config.default_profile);

    let name = name?;
    let profile = config.profiles.get(&name)?;

    Some(ActiveProfile {
        name,
        description: profile.description.clone(),
        commands: profile.commands.clone(),
    })
}

// ── Built-in recommended profiles for `profile init` ──

/// Returns the default configuration template with built-in recommended profiles.
pub fn builtin_config_toml() -> &'static str {
    r#"# falcon-cli profile configuration
#
# Uncomment to set a default profile (applied when --profile is not specified):
# default_profile = "security-ops"

[profiles.security-ops]
description = "Security operations essentials"
commands = [
  "alert", "detection", "incident", "host", "host-group",
  "ioc", "iocs", "intel", "quarantine",
  "spotlight-vuln", "rtr", "rtr-admin",
  "recon", "overwatch", "sandbox", "drift",
  "custom-ioa", "ioa-exclusion", "ml-exclusion",
  "sv-exclusion", "cert-exclusion",
]

[profiles.cloud]
description = "Cloud security management"
commands = [
  "cloud-aws", "cloud-azure", "cloud-connect-aws", "cloud-gcp", "cloud-oci",
  "cloud-policy", "cloud-security", "cloud-asset", "cloud-compliance",
  "cloud-detection", "cloud-snapshot", "cspm", "d4c",
  "container-alert", "container-detection", "container-compliance",
  "container-image", "container-package", "container-vuln",
  "falcon-container", "k8s", "k8s-compliance",
  "unidentified-container", "image-policy",
]

[profiles.ai-agent]
description = "Minimal set for AI agent context"
commands = [
  "alert", "detection", "host", "host-group", "incident",
  "ioc", "spotlight-vuln", "rtr",
]

[profiles.all]
description = "All commands enabled"
commands = ["*"]
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(toml_str: &str) -> ProfileConfig {
        toml::from_str(toml_str).unwrap()
    }

    #[test]
    fn test_parse_config() {
        let config = make_config(
            r#"
default_profile = "test"

[profiles.test]
description = "Test profile"
commands = ["alert", "host"]
"#,
        );
        assert_eq!(config.default_profile.as_deref(), Some("test"));
        assert_eq!(config.profiles.len(), 1);
        let p = config.profiles.get("test").unwrap();
        assert_eq!(p.commands, vec!["alert", "host"]);
    }

    #[test]
    fn test_wildcard() {
        let active = ActiveProfile {
            name: "all".into(),
            description: "All".into(),
            commands: vec!["*".into()],
        };
        assert!(active.is_command_allowed("alert"));
        assert!(active.is_command_allowed("anything"));
    }

    #[test]
    fn test_allowlist() {
        let active = ActiveProfile {
            name: "test".into(),
            description: "".into(),
            commands: vec!["alert".into(), "host".into()],
        };
        assert!(active.is_command_allowed("alert"));
        assert!(active.is_command_allowed("host"));
        assert!(!active.is_command_allowed("detection"));
    }

    #[test]
    fn test_empty_commands() {
        let active = ActiveProfile {
            name: "empty".into(),
            description: "".into(),
            commands: vec![],
        };
        assert!(!active.is_command_allowed("alert"));
    }

    #[test]
    fn test_builtin_config_parses() {
        let config: ProfileConfig = toml::from_str(builtin_config_toml()).unwrap();
        assert!(config.profiles.contains_key("security-ops"));
        assert!(config.profiles.contains_key("cloud"));
        assert!(config.profiles.contains_key("ai-agent"));
        assert!(config.profiles.contains_key("all"));
        assert!(config.default_profile.is_none()); // commented out
    }

    #[test]
    fn test_config_without_default() {
        let config = make_config(
            r#"
[profiles.test]
description = "Test"
commands = ["alert"]
"#,
        );
        assert!(config.default_profile.is_none());
    }
}
