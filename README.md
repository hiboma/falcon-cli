# falcon-cli

A CLI tool for interacting with the CrowdStrike Falcon API, built in Rust.

## Status

Beta - v0.9.0

## Features

- OAuth2 Client Credentials authentication with automatic token refresh
- 105 subcommands covering the CrowdStrike Falcon API
- Extended commands that combine multiple API calls (e.g., `automated-lead`)
- JSON output compatible with jq (default)
- Table output for human-readable display (`--output table`)
- Pretty-printed JSON output (`--pretty`)
- Command profiles to restrict available subcommands per use case
- Shell completion scripts (Bash, Zsh, Fish, PowerShell)
- Cross-platform binaries (Linux, macOS)
- Credential agent for API access isolation

## Installation

### Homebrew

```
brew install hiboma/tap/falcon-cli
```

### GitHub Releases

Download the latest binary from [Releases](https://github.com/hiboma/falcon-cli/releases).

### Cargo with git

```
cargo install --git https://github.com/hiboma/falcon-cli
```

### Build from source

```
cargo install --path .
```

## Configuration

### Environment Variables

Set the following environment variables:

| Variable | Required | Description |
|---|---|---|
| `FALCON_CLIENT_ID` | Yes | CrowdStrike API client ID |
| `FALCON_CLIENT_SECRET` | Yes | CrowdStrike API client secret |
| `FALCON_BASE_URL` | No | API base URL (default: `https://api.crowdstrike.com`) |
| `FALCON_MEMBER_CID` | No | Member CID for MSSP |

CLI options (`--client-id`, `--base-url`, `--member-cid`) override environment variables.

> **Note:** `FALCON_CLIENT_SECRET` has no CLI flag to prevent exposure in process lists. The recommended persistent store is the macOS Keychain (see below). Environment variables, `.env` files, and `credentials.toml` are still supported; ensure any on-disk file has restrictive permissions (`chmod 600`).

### Credential storage (macOS Keychain)

`falcon-cli` resolves the OAuth2 `client_secret` from the following sources, highest priority first:

1. `FALCON_CLIENT_SECRET` environment variable
2. **macOS Keychain** (login keychain, `service=dev.falcon-cli`, `account=client_secret`)
3. `credentials.toml`, searched in this order:
   1. `./.falcon-credentials.toml` (current working directory)
   2. `$XDG_CONFIG_HOME/falcon-cli/credentials.toml` (falls back to `~/.config/falcon-cli/credentials.toml`)

Storing the secret in the Keychain keeps it out of plaintext config files (and out of dotfile backups, Time Machine snapshots, accidental git commits, etc.).

If the Keychain is available but returns a **backend error** (denied prompt, daemon down, ACL mismatch), `falcon-cli` deliberately refuses to fall back to `credentials.toml`. Silently picking up a stale plaintext value would defeat the point of moving the secret into the Keychain in the first place.

#### Storing the secret

```bash
# Interactive prompt (recommended)
falcon-cli credentials set client-secret

# Non-interactive (CI / scripts)
echo "$FALCON_CLIENT_SECRET" | falcon-cli credentials set client-secret --stdin

# Confirm presence (the value is never printed)
falcon-cli credentials status
```

To migrate an existing plaintext `client_secret` from `credentials.toml` into the Keychain in one step:

```bash
falcon-cli credentials migrate
```

`migrate` writes the secret to the Keychain and then offers to dispose of the plaintext copy:

- **Recommended (default)**: the `client_secret` line is removed from the toml via an atomic temp-file rename. No plaintext copy remains on disk.
- **Opt-in**: a 0o600 backup of the original toml is kept alongside the rewritten file. Choose this only if you need to roll back to the old setup.

> ⚠️ **The opt-in backup still contains the plaintext secret.** A backup under `$HOME` is typically included in Time Machine / iCloud / rsync snapshots and defeats the point of moving the secret into the Keychain. Delete it as soon as you have confirmed the new setup works with `falcon-cli credentials status`.

If the rewrite fails partway through, `migrate` rolls back the Keychain entry it just wrote so you are not left in a half-migrated state.

#### Recovering from an interrupted migrate

If you hit Ctrl-C (or your machine loses power) **between** the Keychain write and the toml rewrite, both copies of the secret exist: the new Keychain entry *and* the untouched `credentials.toml`. The process is idempotent — re-running `falcon-cli credentials migrate` on the same file will detect that the secret is still present in the toml and re-run the disposal step. Alternatively, if you want to bail out entirely, `falcon-cli credentials delete client-secret` removes the Keychain entry and the toml stays as it was.

#### Inspecting the entry

The entry lives in your **login** keychain as a `generic password`:

| Attribute | Value |
|---|---|
| Kind | `application password` |
| Service (Name / Where) | `dev.falcon-cli` |
| Account | `client_secret` |

GUI:

```
Keychain Access.app → login → Passwords → search "dev.falcon-cli"
```

CLI (metadata only):

```bash
security find-generic-password -s dev.falcon-cli -a client_secret
```

#### Removing the entry

```bash
falcon-cli credentials delete client-secret
# or via macOS:
security delete-generic-password -s dev.falcon-cli -a client_secret
```

#### Notes on Keychain prompts

macOS shows an access-prompt dialog the first time `falcon-cli` reads the Keychain entry. Choosing **Always Allow** suppresses subsequent prompts.

The dialog reappears whenever the binary's code signature changes — including after every `cargo install` rebuild. This is a macOS ACL behavior, not a `falcon-cli` bug.

If a non-`falcon-cli` build of the binary keeps causing prompts, you can inspect the entry's Access Control list in Keychain Access.app and remove or replace the allowed-applications list.

### Credentials File (TOML)

You can configure credentials using a `credentials.toml` file. Files are loaded in the following order:

1. `./.falcon-credentials.toml` (project-local)
2. `$XDG_CONFIG_HOME/falcon-cli/credentials.toml` (default: `~/.config/falcon-cli/credentials.toml`)

Priority for `client_id` / `base_url` / `member_cid`: CLI arguments > environment variables > credentials.toml.

Priority for `client_secret`: `FALCON_CLIENT_SECRET` > macOS Keychain > credentials.toml. See [Credential storage (macOS Keychain)](#credential-storage-macos-keychain) above.

Template:

```toml
# falcon-cli credentials configuration
#
# Security notes:
#   - This file contains sensitive information
#   - Set file permissions to 0600: chmod 600 credentials.toml
#   - Add to .gitignore to prevent committing to the repository
#   - Consider using environment variables or a secrets manager instead

[credentials]
# CrowdStrike Falcon API OAuth2 client ID (required)
client_id = ""

# CrowdStrike Falcon API OAuth2 client secret (required)
client_secret = ""

# API base URL (optional)
# Default: https://api.crowdstrike.com
# US-2: https://api.us-2.crowdstrike.com
# EU-1: https://api.eu-1.crowdstrike.com
# US-GOV-1: https://api.laggar.gcw.crowdstrike.com
# base_url = "https://api.crowdstrike.com"

# Member CID for MSSP (optional)
# Set this to specify a child tenant in multi-tenant environments
# member_cid = ""
```

Setup:

```bash
# Global configuration (XDG Base Directory)
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/falcon-cli"
cp credentials.toml "${XDG_CONFIG_HOME:-$HOME/.config}/falcon-cli/credentials.toml"
chmod 600 "${XDG_CONFIG_HOME:-$HOME/.config}/falcon-cli/credentials.toml"

# Project-local configuration
cp credentials.toml .falcon-credentials.toml
chmod 600 .falcon-credentials.toml
echo ".falcon-credentials.toml" >> .gitignore
```

### Profiles

Profiles restrict which subcommands are available. This is useful for limiting scope per use case (e.g., security operations, AI agent context).

```bash
# Initialize a profile configuration file
falcon-cli profile init

# List available profiles
falcon-cli profile list

# Use a specific profile
falcon-cli --profile security-ops alert list --limit 10

# Or set via environment variable
export FALCON_PROFILE=ai-agent
falcon-cli alert list --limit 10
```

Profile configuration (`.falcon-cli.toml` or `~/.config/falcon-cli/config.toml`). Run `falcon-cli profile init` to generate a full template with built-in profiles:

```toml
default_profile = "security-ops"

[profiles.security-ops]
description = "Security operations essentials"
commands = ["alert", "detection", "incident", "host", "rtr"]

[profiles.ai-agent]
description = "Minimal set for AI agent context"
commands = ["alert", "detection", "host", "ioc", "spotlight-vuln", "rtr"]

[profiles.all]
description = "All commands enabled"
commands = ["*"]
```

Priority: `--profile` flag > `FALCON_PROFILE` env > `default_profile` in config

## Agent Mode

The credential agent isolates API credentials in a separate process. This enables LLM agents (e.g., Claude Code) to use falcon-cli without direct access to secrets. Credentials are resolved into an in-memory struct before fork, and `FALCON_*` environment variables are cleared from the process to prevent leakage via `/proc/<pid>/environ`.

### Start the agent

```bash
# Start with 1Password secret injection (recommended)
op run --env-file .env.1password -- falcon-cli agent start

# Or with environment variables directly
FALCON_CLIENT_ID=xxx FALCON_CLIENT_SECRET=yyy falcon-cli agent start
```

The agent forks into the background and writes a session file (`session.json`) for cross-terminal auto-detection. Any terminal can use the agent without additional configuration.

### Use commands via agent

When a session file exists, commands automatically route through the agent:

```bash
falcon-cli alert list --filter "status:'new'"
falcon-cli host list --limit 10
```

### Manage the agent

```bash
# Check agent status
falcon-cli agent status

# Stop the current agent
falcon-cli agent stop

# Stop all running agents
falcon-cli agent stop --all

# Run in foreground (for debugging)
falcon-cli agent start --foreground
```

### Agent auto-detection priority

1. `--no-agent` flag — forces direct API mode
2. `FALCON_AGENT_TOKEN` env — connects to agent via socket
3. `session.json` — auto-detects running agent
4. Direct API mode — falls back to direct API calls

### Lifecycle

- The agent shuts down on SIGTERM or SIGINT (signal-only shutdown).
- Use `falcon-cli agent stop` to stop the agent.

For details, see [ADR-0001: Agent Mode for Credential Isolation](docs/adr/0001-daemon-mode-for-credential-isolation.md).

## Usage

### Detection & Response

```bash
# List alerts with a filter
falcon-cli alert list --filter "status:'new'" --limit 10

# Get detection summaries
falcon-cli detection list --filter "status:'new'" --limit 5

# Get incident details
falcon-cli incident get --id <INCIDENT_ID>
```

| Command | Description |
|---|---|
| `alert` | Manage alerts |
| `detection` | Manage detections |
| `incident` | Manage incidents |
| `rtr` | Manage real-time response sessions |
| `rtr-admin` | Manage real-time response (admin) |
| `rtr-audit` | Manage real-time response audit |
| `recon` | Manage recon monitoring rules |
| `overwatch` | Manage OverWatch dashboard |
| `sandbox` | Manage Falcon Intelligence Sandbox |
| `quarantine` | Manage quarantined files |
| `drift` | Manage drift indicators |

### Host Management

```bash
# List hosts with a filter
falcon-cli host list --filter "platform_name:'Linux'" --limit 10

# List host groups
falcon-cli host-group list --limit 10
```

| Command | Description |
|---|---|
| `host` | Manage hosts |
| `host-group` | Manage host groups |
| `host-migration` | Manage host migrations |
| `discover` | Discover assets |
| `device-content` | Manage device content |
| `device-control-policy` | Manage device control policies |

### Policy Management

```bash
# List prevention policies
falcon-cli prevention-policy list --limit 10
```

| Command | Description |
|---|---|
| `prevention-policy` | Manage prevention policies |
| `response-policy` | Manage response policies |
| `sensor-update-policy` | Manage sensor update policies |
| `content-update-policy` | Manage content update policies |
| `firewall-policy` | Manage firewall policies |

### Cloud Security

```bash
# List AWS cloud registrations
falcon-cli cloud-aws list --limit 10

# List cloud security detections
falcon-cli cloud-detection list --limit 10
```

| Command | Description |
|---|---|
| `cloud-aws` | Manage AWS cloud registration |
| `cloud-azure` | Manage Azure cloud registration |
| `cloud-connect-aws` | Manage AWS cloud connections |
| `cloud-gcp` | Manage GCP cloud registration |
| `cloud-oci` | Manage OCI cloud registration |
| `cloud-policy` | Manage cloud policies |
| `cloud-security` | Manage cloud security |
| `cloud-asset` | Manage cloud security assets |
| `cloud-compliance` | Manage cloud security compliance |
| `cloud-detection` | Manage cloud security detections |
| `cloud-snapshot` | Manage cloud snapshots |
| `cspm` | Manage CSPM registration |
| `d4c` | Manage D4C registration |

### Container & Kubernetes

```bash
# List container images
falcon-cli container-image list --limit 10

# List container vulnerabilities
falcon-cli container-vuln list --limit 10
```

| Command | Description |
|---|---|
| `container-alert` | Manage container alerts |
| `container-detection` | Manage container detections |
| `container-compliance` | Manage container image compliance |
| `container-image` | Manage container images |
| `container-package` | Manage container packages |
| `container-vuln` | Manage container vulnerabilities |
| `falcon-container` | Manage Falcon container |
| `k8s` | Manage Kubernetes protection |
| `k8s-compliance` | Manage Kubernetes container compliance |
| `unidentified-container` | Manage unidentified containers |
| `image-policy` | Manage image assessment policies |

### Vulnerability Management

```bash
# List Spotlight vulnerabilities
falcon-cli spotlight-vuln list --filter "status:'open'" --limit 10

# List exposure assets
falcon-cli exposure list --limit 10
```

| Command | Description |
|---|---|
| `spotlight-vuln` | Manage Spotlight vulnerabilities |
| `spotlight-eval` | Manage Spotlight evaluation logic |
| `spotlight-metadata` | Manage Spotlight vulnerability metadata |
| `serverless-vuln` | Manage serverless vulnerabilities |
| `exposure` | Manage exposure |
| `config-assessment` | Manage configuration assessments |
| `config-eval` | Manage configuration assessment evaluation logic |

### Exclusions & IOC

```bash
# List IOC indicators
falcon-cli ioc list --filter "type:'domain'" --limit 20

# List custom IOA rules
falcon-cli custom-ioa list --limit 10
```

| Command | Description |
|---|---|
| `ioa-exclusion` | Manage IOA exclusions |
| `ioc` | Manage IOC indicators |
| `iocs` | Manage IOCs (legacy) |
| `ml-exclusion` | Manage ML exclusions |
| `sv-exclusion` | Manage sensor visibility exclusions |
| `cert-exclusion` | Manage certificate-based exclusions |
| `custom-ioa` | Manage custom IOA rules |

### Threat Intelligence

```bash
# List threat intelligence
falcon-cli intel list --limit 10

# Manage ThreatGraph
falcon-cli threatgraph list
```

| Command | Description |
|---|---|
| `intel` | Manage threat intelligence |
| `intel-feed` | Manage intelligence feeds |
| `intel-graph` | Manage intelligence indicator graph |
| `tailored-intel` | Manage tailored intelligence |
| `threatgraph` | Manage ThreatGraph |
| `malquery` | Manage MalQuery |

### Sensor & Downloads

```bash
# List sensor downloads
falcon-cli sensor-download list --limit 5
```

| Command | Description |
|---|---|
| `sensor-download` | Manage sensor downloads |
| `sensor-usage` | Manage sensor usage |
| `install-token` | Manage installation tokens |
| `download` | Manage downloads |
| `deployment` | Manage deployments |

### Scanning & Compliance

```bash
# List on-demand scans
falcon-cli ods list --limit 10
```

| Command | Description |
|---|---|
| `quick-scan` | Manage quick scans |
| `quick-scan-pro` | Manage quick scans (pro) |
| `ods` | Manage on-demand scans |
| `filevantage` | Manage FileVantage |
| `datascanner` | Manage DataScanner |
| `data-protection` | Manage data protection configuration |

### Identity & Access

```bash
# List users
falcon-cli user list --limit 10
```

| Command | Description |
|---|---|
| `identity` | Manage identity protection |
| `user` | Manage users |
| `oauth2` | Manage OAuth2 tokens |
| `zero-trust` | Manage Zero Trust assessments |
| `mobile` | Manage mobile enrollment |
| `mssp` | Manage MSSP (Flight Control) |

### Monitoring & Reporting

```bash
# List event streams
falcon-cli event-stream list --limit 5

# List workflows
falcon-cli workflow list --limit 10
```

| Command | Description |
|---|---|
| `event-stream` | Manage event streams |
| `message` | Manage message center |
| `report-execution` | Manage report executions |
| `scheduled-report` | Manage scheduled reports |
| `case` | Manage cases |
| `falcon-complete` | Manage Falcon Complete dashboard |
| `workflow` | Manage workflows |
| `it-automation` | Manage IT automation |

### Platform & Integration

```bash
# List API integrations
falcon-cli api-integration list --limit 10

# Get delivery settings
falcon-cli delivery-setting get
```

| Command | Description |
|---|---|
| `api-integration` | Manage API integrations |
| `aspm` | Manage ASPM |
| `cao-hunting` | Manage CAO hunting |
| `correlation-rule` | Manage correlation rules |
| `correlation-admin` | Manage correlation rules (admin) |
| `custom-storage` | Manage custom storage |
| `delivery-setting` | Manage delivery settings |
| `fdr` | Manage FDR |
| `firewall` | Manage firewall rules |
| `logscale` | Manage Foundry LogScale |
| `ngsiem` | Manage NGSIEM |
| `sample` | Manage sample uploads |
| `saas-security` | Manage SaaS security |
| `faas` | Manage FaaS executions |

### Extended Commands

Commands that combine multiple Falcon API calls into a single operation.

```bash
# Investigate automated-lead alerts
falcon-cli automated-lead investigate --filter "status:'new'" --limit 5
```

| Command | Description |
|---|---|
| `automated-lead` | Investigate automated-lead alerts (multi-API) |

### Shell Completion

Generate completion scripts for your shell:

```bash
# Bash
falcon-cli completion bash > /etc/bash_completion.d/falcon-cli

# Zsh
falcon-cli completion zsh > "${fpath[1]}/_falcon-cli"

# Fish
falcon-cli completion fish > ~/.config/fish/completions/falcon-cli.fish

# PowerShell
falcon-cli completion powershell > falcon-cli.ps1
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
cargo deny check
```

`cargo deny check` enforces supply-chain policy (advisories, licenses, bans, sources) declared in `deny.toml`. Install the binary with `cargo install --locked cargo-deny` if it is not yet available locally.

## License

MIT
