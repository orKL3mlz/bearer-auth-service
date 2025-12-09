# Auth Service with JSON Logging

## Overview
A lightweight authentication service built with Node.js and Express. It validates Bearer tokens provided via the `Authorization` header and logs all events in **structured JSON format** for easy parsing and observability.

> [!NOTE]
> Code partially created with AI and checked by me.

## Features
- Listen on port `80`
- Bearer token validation using timing-safe comparison.
- Tokens loaded from environment variables (`TOKEN_<NAME>`).
- **JSON-based logging** for all events (startup, token usage, failures).
- Logs include timestamp, source IP (reverse proxy aware), user agent, token name, masked token value.
- Failure reasons logged for missing, malformed, empty, or invalid tokens.
- Optional log rotation support via `SIGUSR1`.
- Reverse proxy support with configurable `trust proxy`.

## Environment Variables
| Variable | Description | Mandatory | Default |
|----------|-------------|-----------|---------|
| `TOKEN_<NAME>` | Defines a valid token. Example: `TOKEN_BACKOFFICE=abc123`. | Yes | `None` |
| `APP_LOG_STDOUT_PATH` | Path for info/debug logs. | No | `stdout` |
| `APP_LOG_STDERR_PATH` | Path for error logs. | No | `stderr` |
| `TRUST_PROXY` | Configure Express trust proxy. | No | `True` |

## Token creation

> [!WARNING]
> Tokens are read from environement variables.
> The variable should start with `TOKEN_` and should only contain letters and numbers.

## Reverse Proxy Support
> [!WARNING]
> If running behind a reverse proxy (e.g., Traefik, Nginx), set `TRUST_PROXY` to `true` or a suitable value. The service will then correctly interpret `X-Forwarded-For` headers.

## Logging Details
- All logs are emitted as **single-line JSON objects**.
- Example fields:
  - `ts`: ISO timestamp
  - `event`: Event type (`auth_success`, `auth_failure`, `tokens_loaded`, etc.)
  - `source_ip`: Client IP (from `X-Forwarded-For` or socket)
  - `user_agent`: HTTP User-Agent header
  - `token_name`: Name of the token (success only)
  - `token_value_masked`: First 3 characters of token followed by `...`
  - `reason`: Failure reason (for `auth_failure`)
  - `path`, `method`, `status`: HTTP request details

### Log Rotation
Send `SIGUSR1` to the process to reopen log files after rotation.

## Usage
```bash
# Install dependencies
npm install

# Run the service
TOKEN_BACKOFFICE=abc123 npm start
```

### Health Check
```bash
curl http://localhost/health
```

### Auth Check
```bash
curl -H "Authorization: Bearer abc123" http://localhost/auth-check
```

## Example Logs
**Successful Authentication:**
```json
{"ts":"2025-12-09T12:37:32.369Z","event":"auth_success","source_ip":"192.168.16.20","user_agent":"Mozilla/5.0","token_name":"BACKOFFICE","token_value_masked":"abc...","path":"/auth-check","method":"GET","status":200}
```

**Failed Authentication (invalid token):**
```json
{"ts":"2025-12-09T12:37:20.000Z","event":"auth_failure","reason":"invalid_token","source_ip":"192.168.16.20","user_agent":"Mozilla/5.0","token_name":null,"token_value_masked":"bad...","path":"/auth-check","method":"GET","status":401}
```

## Security Notes
- Full token values are never logged; only the first 3 characters are shown.
- Failure responses are generic (`401 Unauthorized`) to avoid leaking details.