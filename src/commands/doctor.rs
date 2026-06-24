//! `falcon-cli doctor` — diagnose configuration, credential resolution, and
//! connectivity without ever printing secret values.
//!
//! Modeled after `jamf-cli doctor`. The command answers four questions for an
//! operator who is debugging "why does falcon-cli not authenticate?":
//!
//! - CONFIG: which config files exist on disk.
//! - RESOLVED: where each credential came from (CLI / env / Keychain / toml),
//!   and whether it resolved at all. Secret values are never shown; `client_id`
//!   is masked too, matching the project's no-leak posture.
//! - ENVIRONMENT: the state of every FALCON_* environment variable.
//! - CONNECTIVITY: an actual OAuth2 token request against base_url, so the
//!   operator sees whether auth succeeds end to end.
//!
//! Security: like `credentials status`, doctor consults the OS credential
//! store (which may prompt on macOS) but prints only presence and provenance.
//! No code path here formats a secret value into stdout/stderr.

use std::path::PathBuf;
use std::time::Instant;

use crate::config::credential_store::{default_store, CredentialStore, KEY_CLIENT_SECRET};
use crate::config::{credentials_search_paths, FalconCredentials};

/// Where a resolved value originated. Mirrors the precedence order in
/// `FalconCredentials::resolve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Cli,
    Env,
    Keychain,
    Toml,
    Default,
    Unset,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Source::Cli => "cli flag",
            Source::Env => "env var",
            Source::Keychain => "keychain",
            Source::Toml => "credentials.toml",
            Source::Default => "built-in default",
            Source::Unset => "unset",
        }
    }
}

/// Inputs that doctor needs from the parsed CLI so it can reproduce the
/// precedence decisions `resolve` makes.
pub struct DoctorInput<'a> {
    pub cli_client_id: Option<&'a str>,
    pub cli_base_url: Option<&'a str>,
    pub cli_member_cid: Option<&'a str>,
    pub cli_profile: Option<&'a str>,
}

/// Entry point for `falcon-cli doctor`. Performs synchronous inspection first,
/// then an async connectivity probe.
pub async fn run(input: DoctorInput<'_>) {
    let version = env!("CARGO_PKG_VERSION");
    println!("falcon-cli {}", version);
    println!();

    report_config();
    println!();
    let creds = report_resolved(&input);
    println!();
    report_active_profile(input.cli_profile);
    println!();
    report_environment();
    println!();
    report_connectivity(&creds).await;
}

// ── CONFIG ──────────────────────────────────────────────────────────────────

/// Show which on-disk config files exist. falcon-cli has two independent files:
/// the profile config (`.falcon-cli.toml` / `~/.config/falcon-cli/config.toml`)
/// and the credentials file (`.falcon-credentials.toml` /
/// `~/.config/falcon-cli/credentials.toml`).
fn report_config() {
    println!("CONFIG");

    let profile_paths = profile_config_search_paths();
    print_file_group("profile config", &profile_paths);

    let cred_paths = credentials_search_paths();
    print_file_group("credentials  ", &cred_paths);
}

/// Profile config search paths, kept in sync with `profile::config_search_paths`.
/// That function is private; we mirror it here rather than widen its visibility
/// just for diagnostics.
fn profile_config_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(".falcon-cli.toml")];
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        paths.push(home.join(".config/falcon-cli/config.toml"));
    }
    paths
}

fn print_file_group(label: &str, paths: &[PathBuf]) {
    match paths.iter().find(|p| p.is_file()) {
        Some(found) => {
            println!("  {}: {}", label, found.display());
            println!("  {}  status: present", " ".repeat(label.len()));
        }
        None => {
            println!("  {}: (none found)", label);
            let searched = paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!("  {}  searched: {}", " ".repeat(label.len()), searched);
        }
    }
}

// ── RESOLVED CREDENTIALS ─────────────────────────────────────────────────────

/// Resolve credentials exactly as the real code path does, then report the
/// provenance of each field. Returns the resolved credentials so the
/// connectivity probe can reuse them.
///
/// Secret values are never printed: `client_secret` shows presence + source,
/// `client_id` shows masked presence + source.
fn report_resolved(input: &DoctorInput) -> FalconCredentials {
    println!("RESOLVED CREDENTIALS");

    let store = default_store();
    let creds = FalconCredentials::resolve_with_store(
        input.cli_client_id,
        input.cli_base_url,
        input.cli_member_cid,
        store.as_deref(),
    );

    // client_id: precedence CLI > env > toml.
    let id_source = resolve_source_plain(
        "--client-id",
        "FALCON_CLIENT_ID",
        toml_field(|f| f.client_id),
    );
    print_masked_field("client-id", creds.client_id.is_some(), id_source);

    // client_secret: precedence env > Keychain > toml. This is the most
    // common failure point, so be explicit about each layer.
    let secret_source = resolve_secret_source(store.as_deref());
    print_secret_field(
        "client-secret",
        creds.client_secret.is_some(),
        secret_source,
    );

    // base_url: precedence CLI > env > toml > built-in default. Always
    // resolves to something, so we can show the value (it is not a secret).
    let url_source =
        resolve_source_plain("--base-url", "FALCON_BASE_URL", toml_field(|f| f.base_url));
    let url_source = url_source.unwrap_or(Source::Default);
    print_field(
        "base-url",
        &format!("{}  ({})", creds.base_url, url_source.label()),
    );

    // member_cid: precedence CLI > env > toml. Optional (MSSP only).
    let cid_source = resolve_source_plain(
        "--member-cid",
        "FALCON_MEMBER_CID",
        toml_field(|f| f.member_cid),
    );
    match (&creds.member_cid, cid_source) {
        (Some(cid), Some(src)) => print_field("member-cid", &format!("{}  ({})", cid, src.label())),
        _ => print_field("member-cid", "(unset)"),
    }

    creds
}

/// Determine the source of a non-secret field using the CLI > env > toml
/// precedence. Returns `None` if the field is unset from every source.
///
/// `cli_flag` is the long-option name (e.g. `--client-id`). We must inspect the
/// raw argv to tell a CLI flag apart from an env var: clap merges both into the
/// same parsed field via `#[arg(env = ...)]`, so the parsed value alone cannot
/// distinguish "passed on the command line" from "read from the environment".
fn resolve_source_plain(cli_flag: &str, env_key: &str, toml_present: bool) -> Option<Source> {
    if cli_flag_present(cli_flag) {
        Some(Source::Cli)
    } else if std::env::var(env_key).is_ok_and(|v| !v.is_empty()) {
        Some(Source::Env)
    } else if toml_present {
        Some(Source::Toml)
    } else {
        None
    }
}

/// Returns true if `flag` (e.g. `--client-id`) was passed on the command line,
/// either as `--flag value` or `--flag=value`.
fn cli_flag_present(flag: &str) -> bool {
    flag_present_in(std::env::args(), flag)
}

/// Pure core of `cli_flag_present`, testable without touching the real argv.
fn flag_present_in<I: IntoIterator<Item = String>>(args: I, flag: &str) -> bool {
    let prefix = format!("{}=", flag);
    args.into_iter()
        .any(|a| a == flag || a.starts_with(&prefix))
}

/// Determine the source of `client_secret`: env > Keychain > toml.
fn resolve_secret_source(store: Option<&dyn CredentialStore>) -> Source {
    if std::env::var("FALCON_CLIENT_SECRET").is_ok_and(|v| !v.is_empty()) {
        return Source::Env;
    }
    // Probe the store. We only care presence vs absence here; backend errors
    // are surfaced separately by `credentials status`, so for doctor we treat
    // any successful Some as keychain-sourced.
    if let Some(store) = store {
        if let Ok(Some(_)) = store.get(KEY_CLIENT_SECRET) {
            return Source::Keychain;
        }
    }
    if toml_field(|f| f.client_secret) {
        return Source::Toml;
    }
    Source::Unset
}

/// Render a non-secret-but-still-masked field (client_id). We show only
/// resolved / not resolved plus the source, never the value.
fn print_masked_field(name: &str, present: bool, source: Option<Source>) {
    match (present, source) {
        (true, Some(src)) => print_field(name, &format!("set  ({})", src.label())),
        // Resolved but we could not attribute a source (should not happen):
        (true, None) => print_field(name, "set"),
        (false, _) => print_field(name, "(unresolved)"),
    }
}

/// Render the secret field (client_secret): presence + source only.
fn print_secret_field(name: &str, present: bool, source: Source) {
    if present {
        print_field(name, &format!("stored  ({})", source.label()));
    } else {
        print_field(name, "(unresolved)");
    }
}

/// Print one `  name:   value` line with the value column aligned. The widest
/// label we use is `client-secret:` (14 chars including the colon), so a column
/// width of 16 leaves at least two spaces before every value.
fn print_field(name: &str, value: &str) {
    let label = format!("{}:", name);
    println!("  {:<16}{}", label, value);
}

// ── credentials.toml probing ─────────────────────────────────────────────────

/// Re-read credentials.toml and test a field for presence without exposing the
/// value. We re-parse here (rather than reuse the private loader in `config`)
/// so doctor can attribute *which source* a value came from independently of
/// the resolved result.
fn toml_field(selector: impl Fn(&CredsTomlView) -> bool) -> bool {
    let Some(view) = load_credentials_toml_view() else {
        return false;
    };
    selector(&view)
}

/// A presence-only view of credentials.toml. Booleans only — we never retain
/// the secret value.
struct CredsTomlView {
    client_id: bool,
    client_secret: bool,
    base_url: bool,
    member_cid: bool,
}

/// Parse a credentials.toml body into a presence-only view. The deserialized
/// secret strings are dropped at the end of this function (only booleans
/// escape), so no secret value lives past this scope.
fn parse_creds_view(content: &str) -> Option<CredsTomlView> {
    #[derive(serde::Deserialize, Default)]
    struct Root {
        #[serde(default)]
        credentials: Fields,
    }
    #[derive(serde::Deserialize, Default)]
    struct Fields {
        client_id: Option<String>,
        client_secret: Option<String>,
        base_url: Option<String>,
        member_cid: Option<String>,
    }

    let root: Root = toml::from_str(content).ok()?;
    let c = root.credentials;
    let non_empty = |o: Option<String>| o.is_some_and(|v| !v.is_empty());
    Some(CredsTomlView {
        client_id: non_empty(c.client_id),
        client_secret: non_empty(c.client_secret),
        base_url: non_empty(c.base_url),
        member_cid: non_empty(c.member_cid),
    })
}

fn load_credentials_toml_view() -> Option<CredsTomlView> {
    for path in credentials_search_paths() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Some(view) = parse_creds_view(&content) {
                return Some(view);
            }
        }
    }
    None
}

// ── ACTIVE PROFILE ───────────────────────────────────────────────────────────

fn report_active_profile(cli_profile: Option<&str>) {
    println!("ACTIVE PROFILE");
    match crate::profile::resolve(cli_profile) {
        Some(ap) => {
            // `cli_profile` is clap-merged (flag or env), so consult argv to
            // distinguish the two — same reason as resolve_source_plain.
            let source = if cli_flag_present("--profile") {
                "cli flag"
            } else if std::env::var("FALCON_PROFILE").is_ok_and(|v| !v.is_empty()) {
                "env var"
            } else {
                "config default-profile"
            };
            println!("  name:     {}  ({})", ap.name, source);
            if !ap.description.is_empty() {
                println!("  desc:     {}", ap.description);
            }
            if ap.commands.iter().any(|c| c == "*") {
                println!("  commands: all");
            } else {
                println!("  commands: {} allowed", ap.commands.len());
            }
        }
        None => {
            println!("  name:     (none)  — all commands enabled");
        }
    }
}

// ── ENVIRONMENT ──────────────────────────────────────────────────────────────

/// The full set of FALCON_* variables falcon-cli reads, including legacy agent
/// vars. Sensitive vars are reported as set/unset only; their value is never
/// printed. `FALCON_CLIENT_ID` is masked alongside the secret/token so that a
/// shared doctor dump cannot leak the client identity (consistent with the
/// RESOLVED section, which also masks client_id).
fn report_environment() {
    println!("ENVIRONMENT");

    // (name, is_sensitive). Sensitive vars show (set)/(unset) only.
    let vars: &[(&str, bool)] = &[
        ("FALCON_CLIENT_ID", true),
        ("FALCON_CLIENT_SECRET", true),
        ("FALCON_BASE_URL", false),
        ("FALCON_MEMBER_CID", false),
        ("FALCON_PROFILE", false),
        ("FALCON_AGENT_SOCKET", false),
        ("FALCON_AGENT_TOKEN", true),
    ];

    for (name, is_sensitive) in vars {
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => {
                if *is_sensitive {
                    println!("  {:<22} (set)", name);
                } else {
                    println!("  {:<22} {}", name, v);
                }
            }
            _ => println!("  {:<22} (unset)", name),
        }
    }
}

// ── CONNECTIVITY ─────────────────────────────────────────────────────────────

/// Probe connectivity by performing a real OAuth2 client-credentials token
/// request against base_url. This is the same call the CLI makes on every
/// command, so a green result here means auth works end to end.
async fn report_connectivity(creds: &FalconCredentials) {
    println!("CONNECTIVITY");

    let config = match creds.to_config() {
        Ok(c) => c,
        Err(_) => {
            println!(
                "  POST {}/oauth2/token  →  SKIPPED (credentials incomplete)",
                creds.base_url
            );
            println!("  hint: client-id and client-secret must both resolve to test auth");
            return;
        }
    };

    let auth = crate::auth::Auth::new(config.clone());
    let url = format!("{}/oauth2/token", config.base_url);

    let start = Instant::now();
    let result = auth.get_token().await;
    let elapsed = start.elapsed().as_millis();

    match result {
        Ok(_) => {
            // Success means a token was issued; we do not print it.
            println!("  POST {}  →  200 OK, token issued ({}ms)", url, elapsed);
        }
        Err(e) => {
            // Auth errors already carry the upstream HTTP status + truncated
            // body (see auth.rs). They do not contain the secret.
            println!("  POST {}  →  FAILED ({}ms)", url, elapsed);
            println!("  {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flag_present_matches_space_form() {
        let a = args(&["falcon-cli", "--client-id", "abc", "doctor"]);
        assert!(flag_present_in(a, "--client-id"));
    }

    #[test]
    fn flag_present_matches_equals_form() {
        let a = args(&["falcon-cli", "--base-url=https://x", "doctor"]);
        assert!(flag_present_in(a, "--base-url"));
    }

    #[test]
    fn flag_present_absent_when_only_env() {
        // No --client-id on the argv even though the value resolved from env.
        let a = args(&["falcon-cli", "doctor"]);
        assert!(!flag_present_in(a, "--client-id"));
    }

    #[test]
    fn flag_present_does_not_match_prefix_of_another_flag() {
        // `--base-url-extra` must not satisfy `--base-url`.
        let a = args(&["falcon-cli", "--base-url-extra", "x", "doctor"]);
        assert!(!flag_present_in(a, "--base-url"));
    }

    #[test]
    fn source_labels_are_stable() {
        assert_eq!(Source::Cli.label(), "cli flag");
        assert_eq!(Source::Env.label(), "env var");
        assert_eq!(Source::Keychain.label(), "keychain");
        assert_eq!(Source::Toml.label(), "credentials.toml");
        assert_eq!(Source::Default.label(), "built-in default");
        assert_eq!(Source::Unset.label(), "unset");
    }

    #[test]
    fn parse_creds_view_detects_present_fields() {
        let toml = r#"
[credentials]
client_id = "id"
client_secret = "secret"
base_url = "https://api.crowdstrike.com"
"#;
        let v = parse_creds_view(toml).unwrap();
        assert!(v.client_id);
        assert!(v.client_secret);
        assert!(v.base_url);
        assert!(!v.member_cid);
    }

    #[test]
    fn parse_creds_view_treats_empty_string_as_absent() {
        let toml = r#"
[credentials]
client_id = ""
client_secret = ""
"#;
        let v = parse_creds_view(toml).unwrap();
        assert!(!v.client_id);
        assert!(!v.client_secret);
    }

    #[test]
    fn parse_creds_view_empty_body_is_all_absent() {
        let v = parse_creds_view("").unwrap();
        assert!(!v.client_id);
        assert!(!v.client_secret);
        assert!(!v.base_url);
        assert!(!v.member_cid);
    }

    #[test]
    fn parse_creds_view_invalid_toml_is_none() {
        assert!(parse_creds_view("this is = not = valid toml [[[").is_none());
    }
}
