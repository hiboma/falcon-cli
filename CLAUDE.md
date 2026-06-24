# CLAUDE.md

## Project Overview

falcon-cli is a Rust CLI tool for interacting with the CrowdStrike Falcon API.

## Build and Test

```
cargo build
cargo test
cargo fmt --check
cargo clippy -- -D warnings
cargo deny check
```

## Authentication

- OAuth2 Client Credentials flow (POST /oauth2/token)
- Priority for `client_id` / `base_url` / `member_cid`: CLI options > env vars > credentials.toml
- Priority for `client_secret`: env var > macOS Keychain > credentials.toml
- Tokens are held in memory only (no file persistence)
- Recommended persistent store for `client_secret` is the macOS Keychain via `falcon-cli credentials set client-secret`
- See `docs/adr/0005-keychain-backed-client-secret.md` for the resolve order, StoreError policy, and migrate flow

## Environment Variables

- `FALCON_CLIENT_ID` - API client ID (required for direct mode)
- `FALCON_CLIENT_SECRET` - API client secret (optional; overrides Keychain when set)
- `FALCON_BASE_URL` - Base URL (default: https://api.crowdstrike.com)
- `FALCON_MEMBER_CID` - Member CID for MSSP (optional)
- `FALCON_AGENT_SOCKET` - Agent Unix socket path (legacy, used by `--socket` flag)
- `FALCON_AGENT_TOKEN` - Agent session token (legacy, triggers agent routing when set)

## Credential Store (macOS Keychain)

- Backend: `keyring` crate with `apple-native` feature
- Keychain entry: `service=dev.falcon-cli`, `account=client_secret` in the login keychain
- `StoreError::Unavailable` → falls through to `credentials.toml`
- `StoreError::Backend` → does NOT fall through (prevents stale-toml override after Keychain migration)
- `classify_keyring_err` downcasts to `security_framework::base::Error` and matches OSStatus `errSecNoDefaultKeychain` (-25307) / `errSecInvalidKeychain` (-25295), so locale-translated error messages (Japanese macOS etc.) still classify correctly
- `falcon-cli credentials {set,delete,status,migrate}` manages entries; `get` is intentionally not provided to prevent AI-agent context leakage

## Diagnostics (`doctor`)

- `falcon-cli doctor` reports CONFIG / RESOLVED CREDENTIALS / ACTIVE PROFILE / ENVIRONMENT / CONNECTIVITY, modeled after `jamf-cli doctor`
- Handled in `main.rs` before the pre-fork `resolve()` (like `credentials`), so it bypasses agent routing and profile gating and does not consult the Keychain twice. It builds its own tokio runtime for the connectivity probe
- Secret values are NEVER printed: `client_id` / `client_secret` show presence + source only; `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` / `FALCON_AGENT_TOKEN` are masked in the ENVIRONMENT section
- Credential provenance (cli flag vs env var) is decided by inspecting raw argv via `cli_flag_present`, because clap merges `--flag` and `#[arg(env = ...)]` into the same parsed field
- CONNECTIVITY performs a real `POST /oauth2/token`; it is skipped when `client_id` / `client_secret` do not both resolve

## Agent Mode

- `falcon-cli agent start` forks a background agent and writes `session.json`
- Any terminal auto-detects the agent via `session.json` (cross-terminal)
- Each agent uses a PID-based unique socket path (`falcon-<PID>.sock`)
- Credentials are resolved into `FalconCredentials` before fork; `FALCON_*` env vars are cleared pre-fork
- The `overwrite_environ_value()` function scrubs the C `environ` array to prevent `/proc/<pid>/environ` leakage
- Signal-only shutdown (SIGTERM/SIGINT); no watchdog or session leader monitoring
- Duplicate start is detected via session.json + socket connection check
- `fork()` must happen before tokio runtime creation (see `main.rs`)
- `--no-agent` flag forces direct API mode, skipping agent auto-detection
- Priority: `--no-agent` > `FALCON_AGENT_TOKEN` env > session.json > direct mode

## Code Quality

- `cargo fmt --check` and `cargo clippy -- -D warnings` must pass
- POSIX compliant (newline at end of files)
- Conventional Commits for commit messages

## Security

- Minimize GitHub Actions permissions
- Pin all third-party actions by commit hash
- Validate all user input strictly
- Use `pull_request` (not `pull_request_target`)
- Supply chain checks via `cargo-deny` (advisories, licenses, bans, sources) are enforced in CI. Policy lives in `deny.toml`.

## Testing

- `cargo test` for unit and integration tests
- Race condition checks with `--test-threads=1` when needed
