# Authentication

## OAuth2 Client Credentials

CrowdStrike Falcon API uses OAuth2 Client Credentials grant.

### Token Request

- Endpoint: `POST /oauth2/token`
- Content-Type: `application/x-www-form-urlencoded`
- Parameters:
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

## Token Lifecycle

1. Token is requested on first API call
2. Token is cached in memory (never persisted to disk)
3. On 401 response, token is invalidated and re-requested
4. Write lock prevents concurrent token refresh (double-check pattern)

## Configuration Priority

1. CLI options (--client-id, --client-secret)
2. Environment variables (FALCON_CLIENT_ID, FALCON_CLIENT_SECRET)
