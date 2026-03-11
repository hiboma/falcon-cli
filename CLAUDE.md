# CLAUDE.md

## Project Overview

falcon-cli is a Rust CLI tool for interacting with the CrowdStrike Falcon API.

## Build and Test

```
cargo build
cargo test
cargo fmt --check
cargo clippy -- -D warnings
```

## Authentication

- OAuth2 Client Credentials flow (POST /oauth2/token)
- Priority: CLI options > environment variables
- Tokens are held in memory only (no file persistence)

## Environment Variables

- `FALCON_CLIENT_ID` - API client ID (required for direct mode)
- `FALCON_CLIENT_SECRET` - API client secret (required for direct mode)
- `FALCON_BASE_URL` - Base URL (default: https://api.crowdstrike.com)
- `FALCON_MEMBER_CID` - Member CID for MSSP (optional)
- `FALCON_DAEMON_SOCKET` - Daemon Unix socket path (set by daemon start)
- `FALCON_DAEMON_TOKEN` - Daemon session token (set by daemon start, triggers auto-detection)

## Daemon Mode

- `eval "$(falcon-cli daemon start)"` forks a background daemon (ssh-agent style)
- `FALCON_DAEMON_TOKEN` in env triggers automatic daemon routing (no flags needed)
- Each daemon uses a PID-based unique socket path (`falcon-<PID>.sock`)
- Watchdog monitors parent shell liveness and 8-hour idle timeout
- `fork()` must happen before tokio runtime creation (see `main.rs`)

## Code Quality

- `cargo fmt --check` and `cargo clippy -- -D warnings` must pass
- POSIX compliant (newline at end of files)
- Conventional Commits for commit messages

## Security

- Minimize GitHub Actions permissions
- Pin all third-party actions by commit hash
- Validate all user input strictly
- Use `pull_request` (not `pull_request_target`)

## Testing

- `cargo test` for unit and integration tests
- Race condition checks with `--test-threads=1` when needed
