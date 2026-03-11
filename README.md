# falcon-cli

A CLI tool for interacting with the CrowdStrike Falcon API, built in Rust.

## Status

Beta - v0.1.0

## Features

- OAuth2 Client Credentials authentication with automatic token refresh
- 105 subcommands covering the full CrowdStrike Falcon API
- JSON output compatible with jq (default)
- Table output for human-readable display (`--output table`)
- Cross-platform binaries (Linux, macOS, Windows)

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

Set the following environment variables:

| Variable | Required | Description |
|---|---|---|
| `FALCON_CLIENT_ID` | Yes | CrowdStrike API client ID |
| `FALCON_CLIENT_SECRET` | Yes | CrowdStrike API client secret |
| `FALCON_BASE_URL` | No | API base URL (default: `https://api.crowdstrike.com`) |
| `FALCON_MEMBER_CID` | No | Member CID for MSSP |

CLI options (`--client-id`, `--base-url`, `--member-cid`) override environment variables.

> **Note:** `FALCON_CLIENT_SECRET` is only configurable via environment variable or `.env` file to prevent exposure in process lists. Ensure `.env` files have restrictive permissions (`chmod 600 .env`).

## Usage

### Security Operations

Commands for managing hosts, detections, incidents, alerts, and response sessions.

```bash
# List hosts with a filter
falcon-cli host list --filter "platform_name:'Linux'" --limit 10

# Get detection summaries
falcon-cli detection list --filter "status:'new'" --limit 5

# Get incident details
falcon-cli incident get --id <INCIDENT_ID>
```

| Command | Description |
|---|---|
| `host` | Manage hosts |
| `detection` | Manage detections |
| `incident` | Manage incidents |
| `alert` | Manage alerts |
| `quarantine` | Manage quarantined files |
| `rtr` | Manage real-time response sessions |
| `rtr-admin` | Manage real-time response (admin) |
| `rtr-audit` | Manage real-time response audit |

### Policies

Commands for managing security policies.

```bash
# List prevention policies
falcon-cli prevention-policy list --limit 10

# Get device control policy details
falcon-cli device-control-policy get --id <POLICY_ID>
```

| Command | Description |
|---|---|
| `prevention-policy` | Manage prevention policies |
| `device-control-policy` | Manage device control policies |
| `firewall-policy` | Manage firewall policies |
| `sensor-update-policy` | Manage sensor update policies |
| `response-policy` | Manage response policies |
| `content-update-policy` | Manage content update policies |
| `ioa-exclusion` | Manage IOA exclusions |

### Threat Intelligence

Commands for threat intelligence and indicator management.

```bash
# List threat actors
falcon-cli intel list --limit 10

# List IOC indicators
falcon-cli ioc list --filter "type:'domain'" --limit 20

# List recon monitoring rules
falcon-cli recon list --limit 10
```

| Command | Description |
|---|---|
| `intel` | Manage threat intelligence |
| `intel-feed` | Manage intelligence feeds |
| `intel-graph` | Manage intelligence indicator graph |
| `ioc` | Manage IOC indicators |
| `iocs` | Manage IOCs (legacy) |
| `custom-ioa` | Manage custom IOA rules |
| `malquery` | Manage MalQuery |
| `sandbox` | Manage Falcon Intelligence Sandbox |
| `recon` | Manage recon monitoring rules |
| `tailored-intel` | Manage tailored intelligence |

### Host Management

Commands for managing host groups, sensors, and exclusions.

```bash
# List host groups
falcon-cli host-group list --limit 10

# List sensor downloads
falcon-cli sensor-download list --limit 5
```

| Command | Description |
|---|---|
| `host-group` | Manage host groups |
| `host-migration` | Manage host migrations |
| `sensor-download` | Manage sensor downloads |
| `sensor-usage` | Manage sensor usage |
| `sv-exclusion` | Manage sensor visibility exclusions |
| `ml-exclusion` | Manage ML exclusions |
| `install-token` | Manage installation tokens |

### Cloud Security

Commands for multi-cloud security posture management.

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
| `cloud-gcp` | Manage GCP cloud registration |
| `cloud-oci` | Manage OCI cloud registration |
| `cloud-connect-aws` | Manage AWS cloud connections |
| `cloud-policy` | Manage cloud policies |
| `cloud-security` | Manage cloud security |
| `cloud-asset` | Manage cloud security assets |
| `cloud-compliance` | Manage cloud security compliance |
| `cloud-detection` | Manage cloud security detections |
| `cloud-snapshot` | Manage cloud snapshots |
| `cspm` | Manage CSPM registration |
| `d4c` | Manage D4C registration |
| `config-assessment` | Manage configuration assessments |

### Container Security

Commands for container and Kubernetes workload security.

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
| `container-image` | Manage container images |
| `container-compliance` | Manage container image compliance |
| `container-package` | Manage container packages |
| `container-vuln` | Manage container vulnerabilities |
| `falcon-container` | Manage Falcon container |
| `k8s` | Manage Kubernetes protection |
| `k8s-compliance` | Manage Kubernetes container compliance |

### Vulnerability Management

Commands for vulnerability and exposure management.

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
| `exposure` | Manage exposure |
| `serverless-vuln` | Manage serverless vulnerabilities |
| `drift` | Manage drift indicators |
| `unidentified-container` | Manage unidentified containers |
| `image-policy` | Manage image assessment policies |
| `config-eval` | Manage configuration assessment evaluation logic |

### Monitoring

Commands for monitoring and dashboards.

```bash
# List event streams
falcon-cli event-stream list --limit 5

# Get ThreatGraph edge types
falcon-cli threatgraph list
```

| Command | Description |
|---|---|
| `event-stream` | Manage event streams |
| `falcon-complete` | Manage Falcon Complete dashboard |
| `overwatch` | Manage OverWatch dashboard |
| `filevantage` | Manage FileVantage |
| `firewall` | Manage firewall rules |
| `discover` | Discover assets |
| `identity` | Manage identity protection |
| `zero-trust` | Manage Zero Trust assessments |
| `threatgraph` | Manage ThreatGraph |

### Administration

Commands for platform administration.

```bash
# List users
falcon-cli user list --limit 10

# List workflows
falcon-cli workflow list --limit 10

# Get delivery settings
falcon-cli delivery-setting get
```

| Command | Description |
|---|---|
| `user` | Manage users |
| `oauth2` | Manage OAuth2 tokens |
| `mssp` | Manage MSSP (Flight Control) |
| `message` | Manage message center |
| `case` | Manage cases |
| `workflow` | Manage workflows |
| `scheduled-report` | Manage scheduled reports |
| `report-execution` | Manage report executions |
| `device-content` | Manage device content |
| `deployment` | Manage deployments |
| `delivery-setting` | Manage delivery settings |
| `data-protection` | Manage data protection configuration |
| `cert-exclusion` | Manage certificate-based exclusions |

### Other

Additional commands for various services.

```bash
# List API integrations
falcon-cli api-integration list --limit 10

# List on-demand scans
falcon-cli ods list --limit 10
```

| Command | Description |
|---|---|
| `api-integration` | Manage API integrations |
| `aspm` | Manage ASPM |
| `cao-hunting` | Manage CAO hunting |
| `correlation-rule` | Manage correlation rules |
| `correlation-admin` | Manage correlation rules (admin) |
| `custom-storage` | Manage custom storage |
| `datascanner` | Manage DataScanner |
| `download` | Manage downloads |
| `faas` | Manage FaaS executions |
| `fdr` | Manage FDR |
| `logscale` | Manage Foundry LogScale |
| `it-automation` | Manage IT automation |
| `mobile` | Manage mobile enrollment |
| `ngsiem` | Manage NGSIEM |
| `ods` | Manage on-demand scans |
| `quick-scan` | Manage quick scans |
| `quick-scan-pro` | Manage quick scans (pro) |
| `saas-security` | Manage SaaS security |
| `sample` | Manage sample uploads |

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
