# CLI Design

## Command Structure

```
falcon-cli <resource> <action> [options]
```

## AI-Friendly Help

- Help text includes response field descriptions for each command
- Minimal syntax highlighting to improve readability in plain terminals
- Consistent structure across all subcommands

## Resources

### host

| Action | Description | Endpoint |
|---|---|---|
| list | List host AIDs | GET /devices/queries/devices/v1 |
| get | Get host details | GET /devices/entities/devices/v2 |

### detection

| Action | Description | Endpoint |
|---|---|---|
| list | List detection IDs | GET /detects/queries/detects/v1 |
| get | Get detection details | GET /detects/entities/summaries/GET/v1 |

## Global Options

| Option | Environment Variable | Description |
|---|---|---|
| --client-id | FALCON_CLIENT_ID | API client ID |
| --client-secret | FALCON_CLIENT_SECRET | API client secret |
| --base-url | FALCON_BASE_URL | API base URL |
| --member-cid | FALCON_MEMBER_CID | MSSP member CID |

## Output

- Default: JSON (pretty-printed)
- All output goes to stdout for jq compatibility
- Errors go to stderr
