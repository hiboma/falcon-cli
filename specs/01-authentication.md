# Authentication

## OAuth2 Client Credentials

CrowdStrike Falcon API uses OAuth2 Client Credentials grant.

### Token Request

- Endpoint: `POST /oauth2/token`
- Content-Type: `application/x-www-form-urlencoded`
- Parameters:
  - `grant_type=client_credentials` (required)
  - `client_id` (required)
  - `client_secret` (required)
  - `member_cid` (optional, for MSSP)

### Token Response

```
{
  "access_token": "...",
  "expires_in": 1799,
  "token_type": "bearer"
}
```

The client requires `token_type` and accepts it only when it equals `bearer`
case-insensitively. `expires_in` is accepted when present.

## Transport Security

- Credential-bearing token requests do not follow redirects.
- Bearer API requests do not follow redirects.
- `base_url` must use HTTPS. HTTP is accepted only for loopback hosts used by
  local development and tests.
- OAuth error bodies are read with an 8 KiB bound, truncated on a UTF-8
  character boundary, and escaped before terminal or log output.

## Token Lifecycle

1. Token is requested on first API call
2. Token is cached in memory (never persisted to disk)
3. On 401 response, token is invalidated and re-requested
4. Write lock prevents concurrent token refresh (double-check pattern)

## Configuration Priority

1. CLI options (`--client-id`, `--base-url`, `--member-cid`)
2. Environment variables (`FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`,
   `FALCON_BASE_URL`, `FALCON_MEMBER_CID`)
3. macOS Keychain for `client_secret`
4. credentials.toml

An environment or Keychain secret is rejected when it would be combined with
identity or destination fields from project-local `.falcon-credentials.toml`.
