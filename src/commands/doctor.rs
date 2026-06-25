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

use crate::config::credential_store::{
    default_store, CredentialStore, StoreError, KEY_CLIENT_SECRET,
};
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

    // Read the credential store exactly once. `resolve_with_store` consults it
    // for the secret, and we also need its result to attribute the secret's
    // source — so we wrap the real store in a recording proxy and reuse the
    // captured lookup, rather than calling `store.get()` a second time (which
    // would risk a second macOS Keychain prompt). `recorder` is Some exactly
    // when `store` is Some, so the recorder is the only probe we ever pass.
    let store = default_store();
    let recorder = store.as_deref().map(RecordingStore::new);
    let probe: Option<&dyn CredentialStore> = recorder.as_ref().map(|r| r as &dyn CredentialStore);

    let creds = FalconCredentials::resolve_with_store(
        input.cli_client_id,
        input.cli_base_url,
        input.cli_member_cid,
        probe,
    );

    // Parse credentials.toml once and reuse the presence flags for every field,
    // rather than re-reading + re-parsing the file per field.
    let toml = load_credentials_toml_view();
    let toml_has = |present: fn(&CredsTomlView) -> bool| toml.as_ref().is_some_and(present);

    // client_id: precedence CLI > env > toml.
    let id_source =
        resolve_source_plain("--client-id", "FALCON_CLIENT_ID", toml_has(|f| f.client_id));
    print_masked_field("client-id", creds.client_id.is_some(), id_source);

    // client_secret: precedence env > Keychain > toml. This is the most common
    // failure point, so be explicit about each layer. We reuse the Keychain
    // result captured during resolve above instead of probing a second time.
    let secret_keychain = recorder
        .as_ref()
        .and_then(|r| r.last_secret_outcome())
        .unwrap_or(KeychainOutcome::Skipped);
    let secret_source = secret_source(secret_keychain, toml_has(|f| f.client_secret));
    print_secret_field(
        "client-secret",
        creds.client_secret.is_some(),
        secret_source,
    );

    // base_url: precedence CLI > env > toml > built-in default. Always
    // resolves to something, so we can show the value (it is not a secret).
    let url_source =
        resolve_source_plain("--base-url", "FALCON_BASE_URL", toml_has(|f| f.base_url));
    let url_source = url_source.unwrap_or(Source::Default);
    print_field(
        "base-url",
        &format!("{}  ({})", creds.base_url, url_source.label()),
    );

    // member_cid: precedence CLI > env > toml. Optional (MSSP only).
    let cid_source = resolve_source_plain(
        "--member-cid",
        "FALCON_MEMBER_CID",
        toml_has(|f| f.member_cid),
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
///
/// An empty env var (`FALCON_CLIENT_ID=`) counts as "set" here, matching
/// `FalconCredentials::resolve`, which uses `std::env::var(..).ok()` and so
/// adopts an empty string rather than falling through to toml. doctor must
/// report the same provenance the real resolve would pick.
fn resolve_source_plain(cli_flag: &str, env_key: &str, toml_present: bool) -> Option<Source> {
    if cli_flag_present(cli_flag) {
        Some(Source::Cli)
    } else if std::env::var(env_key).is_ok() {
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

/// Outcome of consulting the credential store for `client_secret`, captured
/// once during resolve and reused so doctor never probes the Keychain twice.
/// The split between `Unavailable` and `BackendError` mirrors `StoreError`'s
/// two variants, because `resolve` treats them differently (one falls through
/// to toml, the other does not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeychainOutcome {
    /// No store consulted (non-macOS build, or store was None).
    Skipped,
    /// Store returned a secret.
    Found,
    /// Store reports the secret is not stored.
    NotStored,
    /// Store as a whole is not present (CI sandbox without a default keychain,
    /// non-macOS). `resolve` falls through to toml in this case.
    Unavailable,
    /// Store backend access failure (denied prompt, daemon down, ACL mismatch).
    /// `resolve` does NOT fall through to toml in this case.
    BackendError,
}

/// Determine the source of `client_secret`, reproducing the exact precedence in
/// `FalconCredentials::resolve`: env (incl. empty) > Keychain > toml.
///
/// The two Keychain error kinds diverge, matching `config::read_secret_from_store`
/// (ADR 0005): an `Unavailable` store falls through to toml (the migration story
/// must work where no Keychain exists), while a `BackendError` short-circuits to
/// `Unset` — falling back to a stale plaintext toml secret would defeat the
/// point of moving the secret into the Keychain.
fn secret_source(keychain: KeychainOutcome, toml_present: bool) -> Source {
    if std::env::var("FALCON_CLIENT_SECRET").is_ok() {
        return Source::Env;
    }
    match keychain {
        KeychainOutcome::Found => Source::Keychain,
        KeychainOutcome::BackendError => Source::Unset,
        KeychainOutcome::Skipped | KeychainOutcome::NotStored | KeychainOutcome::Unavailable => {
            if toml_present {
                Source::Toml
            } else {
                Source::Unset
            }
        }
    }
}

/// A `CredentialStore` that wraps the real store and records the outcome of the
/// last `get(client_secret)` call. This lets doctor consult the Keychain a
/// single time — `resolve_with_store` reads through it, and we then inspect the
/// captured outcome to attribute the secret's source, instead of issuing a
/// second `get()` (which on macOS could trigger a second access prompt).
struct RecordingStore<'a> {
    inner: &'a dyn CredentialStore,
    last_secret: std::cell::Cell<Option<KeychainOutcome>>,
}

impl<'a> RecordingStore<'a> {
    fn new(inner: &'a dyn CredentialStore) -> Self {
        Self {
            inner,
            last_secret: std::cell::Cell::new(None),
        }
    }

    /// The outcome of the most recent `get(client_secret)`, if any happened.
    fn last_secret_outcome(&self) -> Option<KeychainOutcome> {
        self.last_secret.get()
    }
}

impl CredentialStore for RecordingStore<'_> {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let result = self.inner.get(key);
        if key == KEY_CLIENT_SECRET {
            let outcome = match &result {
                Ok(Some(_)) => KeychainOutcome::Found,
                Ok(None) => KeychainOutcome::NotStored,
                // Distinguish the two error kinds: resolve falls through to toml
                // for Unavailable but not for Backend (see secret_source).
                Err(StoreError::Unavailable(_)) => KeychainOutcome::Unavailable,
                Err(StoreError::Backend(_)) => KeychainOutcome::BackendError,
            };
            self.last_secret.set(Some(outcome));
        }
        result
    }

    fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.inner.set(key, value)
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.inner.delete(key)
    }
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

/// A presence-only view of credentials.toml. Booleans only — we never retain
/// the secret value. doctor parses the file once into this view and reads each
/// field's presence flag, so it can attribute *which source* a value came from
/// independently of the resolved result without re-reading the file per field.
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
        // Treat an empty value as "set", matching FalconCredentials::resolve
        // (which uses std::env::var(..).ok() and so adopts an empty string).
        // Reporting empty as "(unset)" here would contradict the RESOLVED
        // section, which attributes the value to the env var.
        match std::env::var(name) {
            Ok(_) if *is_sensitive => println!("  {:<22} (set)", name),
            Ok(v) if v.is_empty() => println!("  {:<22} (set, empty)", name),
            Ok(v) => println!("  {:<22} {}", name, v),
            Err(_) => println!("  {:<22} (unset)", name),
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

    // `secret_source` reads FALCON_CLIENT_SECRET, a process-global. Serialize
    // these cases and clear the var around each so they cannot race.
    static SECRET_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_secret_env_cleared<F: FnOnce()>(f: F) {
        let _guard = SECRET_ENV_LOCK.lock().unwrap();
        let saved = std::env::var("FALCON_CLIENT_SECRET").ok();
        unsafe { std::env::remove_var("FALCON_CLIENT_SECRET") };
        f();
        unsafe {
            match saved {
                Some(v) => std::env::set_var("FALCON_CLIENT_SECRET", v),
                None => std::env::remove_var("FALCON_CLIENT_SECRET"),
            }
        }
    }

    #[test]
    fn secret_source_env_wins_even_when_empty() {
        let _guard = SECRET_ENV_LOCK.lock().unwrap();
        let saved = std::env::var("FALCON_CLIENT_SECRET").ok();
        // Empty env var still counts as "set" (matches resolve's `.ok()`).
        unsafe { std::env::set_var("FALCON_CLIENT_SECRET", "") };
        assert_eq!(secret_source(KeychainOutcome::Found, true), Source::Env);
        unsafe {
            match saved {
                Some(v) => std::env::set_var("FALCON_CLIENT_SECRET", v),
                None => std::env::remove_var("FALCON_CLIENT_SECRET"),
            }
        }
    }

    #[test]
    fn secret_source_keychain_found() {
        with_secret_env_cleared(|| {
            assert_eq!(
                secret_source(KeychainOutcome::Found, true),
                Source::Keychain
            );
        });
    }

    #[test]
    fn secret_source_backend_error_does_not_fall_back_to_toml() {
        with_secret_env_cleared(|| {
            // Even with a toml secret present, a Keychain backend error must
            // report Unset — resolve refuses the toml fallback (ADR 0005).
            assert_eq!(
                secret_source(KeychainOutcome::BackendError, true),
                Source::Unset
            );
        });
    }

    #[test]
    fn secret_source_falls_through_to_toml() {
        with_secret_env_cleared(|| {
            assert_eq!(
                secret_source(KeychainOutcome::NotStored, true),
                Source::Toml
            );
            assert_eq!(secret_source(KeychainOutcome::Skipped, true), Source::Toml);
            // An Unavailable store (no default keychain) also falls through, so
            // the migration story works where no Keychain exists.
            assert_eq!(
                secret_source(KeychainOutcome::Unavailable, true),
                Source::Toml
            );
        });
    }

    #[test]
    fn secret_source_unset_when_nothing_resolves() {
        with_secret_env_cleared(|| {
            assert_eq!(
                secret_source(KeychainOutcome::NotStored, false),
                Source::Unset
            );
        });
    }

    #[test]
    fn recording_store_captures_secret_outcome() {
        use crate::config::credential_store::test_support::MemoryStore;
        let mem = MemoryStore::new();
        mem.set(KEY_CLIENT_SECRET, "v").unwrap();
        let rec = RecordingStore::new(&mem);
        assert_eq!(rec.last_secret_outcome(), None);
        let _ = rec.get(KEY_CLIENT_SECRET);
        assert_eq!(rec.last_secret_outcome(), Some(KeychainOutcome::Found));

        let empty = MemoryStore::new();
        let rec2 = RecordingStore::new(&empty);
        let _ = rec2.get(KEY_CLIENT_SECRET);
        assert_eq!(rec2.last_secret_outcome(), Some(KeychainOutcome::NotStored));
    }

    #[test]
    fn recording_store_maps_backend_error() {
        use crate::config::credential_store::test_support::FailingStore;
        let failing = FailingStore;
        let rec = RecordingStore::new(&failing);
        let _ = rec.get(KEY_CLIENT_SECRET);
        // FailingStore returns StoreError::Backend, which must map to
        // BackendError (no toml fallback), not Unavailable.
        assert_eq!(
            rec.last_secret_outcome(),
            Some(KeychainOutcome::BackendError)
        );
    }
}
