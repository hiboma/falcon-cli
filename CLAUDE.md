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
- `FALCON_AGENT_SOCKET` - Agent Unix socket path (set by agent start)
- `FALCON_AGENT_TOKEN` - Agent session token (set by agent start, triggers auto-detection)

## Agent Mode (ssh-agent model)

- `eval "$(falcon-cli agent start)"` forks a background agent (ssh-agent style)
- `FALCON_AGENT_TOKEN` in env triggers automatic agent routing (no flags needed)
- Each agent uses a PID-based unique socket path (`falcon-<PID>.sock`)
- Watchdog monitors terminal session liveness (`getsid`) and 8-hour idle timeout
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
