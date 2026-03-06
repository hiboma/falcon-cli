# Error Handling

## Error Types

| Variant | Description |
|---|---|
| Auth | Authentication failures (invalid credentials, token errors) |
| Api | API-level errors (non-2xx responses) |
| Http | Network-level errors (connection, timeout) |
| Json | JSON parsing errors |
| Config | Configuration errors (missing required values) |

## Error Output

- All errors are written to stderr
- Error messages include context (HTTP status, response body)
- Exit code 1 for any error

## Retry Strategy

- On 401: invalidate token, re-authenticate once, retry the request
- No automatic retry for other errors
