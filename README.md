# falcon-cli

A CLI tool for interacting with the CrowdStrike Falcon API, built in Rust.

## Status

Beta - v0.1.0

## Features

- OAuth2 Client Credentials authentication with automatic token refresh
- Host management (list, get details)
- Detection management (list, get details)
- JSON output compatible with jq
- Cross-platform binaries (Linux, macOS, Windows)

## Installation

### Homebrew

```
brew install hiboma/tap/falcon-cli
```

### GitHub Releases

Download the latest binary from [Releases](https://github.com/hiboma/falcon-cli/releases).

### Build from source

```
cargo install --path .
```

## Configuration

Set the following environment variables:

| Variable | Required | Description |
|---|---|---|
| `FALCON_CLIENT_ID` | Yes | CrowdStrike API client ID |
| `FALCON_CLIENT_SECRET` | Yes | CrowdStrike API client secret |
| `FALCON_BASE_URL` | No | API base URL (default: `https://api.crowdstrike.com`) |
| `FALCON_MEMBER_CID` | No | Member CID for MSSP |

CLI options (`--client-id`, `--client-secret`, `--base-url`, `--member-cid`) override environment variables.

## Usage

```
# List hosts
falcon-cli host list --limit 10

# Get host details
falcon-cli host get --id <AID>

# List detections
falcon-cli detection list --filter "status:'new'"

# Get detection details
falcon-cli detection get --id <DETECTION_ID>
```

## Development

### Requirements

- Rust (stable)

### Commands

```
cargo build
cargo test
cargo fmt --check
cargo clippy -- -D warnings
```

## License

MIT
