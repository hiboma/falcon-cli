# Configuration

## Priority Order

1. CLI options (highest priority)
2. Environment variables (lowest priority)

## Required Settings

| Setting | CLI Option | Environment Variable |
|---|---|---|
| Client ID | --client-id | FALCON_CLIENT_ID |
| Client Secret | --client-secret | FALCON_CLIENT_SECRET |

## Optional Settings

| Setting | CLI Option | Environment Variable | Default |
|---|---|---|---|
| Base URL | --base-url | FALCON_BASE_URL | https://api.crowdstrike.com |
| Member CID | --member-cid | FALCON_MEMBER_CID | (none) |

## Security

- Credentials are never written to disk
- Tokens are held in memory only
- Environment variables are read once at startup
