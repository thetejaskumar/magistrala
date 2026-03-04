# SSO Service Deployment and Validation Guide

## Quick Start

### 1. Build the SSO Service

```bash
cd /home/user/sandbox/iot/magistrala
make sso
```

This builds the binary at `build/sso`.

### 2. Run the Service Locally

```bash
# Set required environment variables
export MG_SSO_LOG_LEVEL=debug
export MG_SSO_FRONTEND_URL=http://localhost:3000
export SMQ_USERS_URL=http://localhost:9002

# Run the service
./build/sso
```

The service will start on port `9030` by default.

### 3. Test the SSO Callback Endpoint

```bash
# Generate a test SSO token (for testing only - see below for JWT format)
curl -v "http://localhost:9030/health"

# Test callback with a dummy token (will fail validation but shows endpoint works)
curl -v "http://localhost:9030/sso/callback?token=dummy.token"
```

## Integration with Existing Infrastructure

### 1. Add SSO to the Services List

Edit `Makefile` line 6, add `sso` to the SERVICES list:

```makefile
SERVICES = bootstrap provision re postgres-writer postgres-reader timescale-writer timescale-reader cli alarms reports sso
```

### 2. Add to Docker Compose

Add to `docker/docker-compose.yaml`:

```yaml
sso:
  image: ghcr.io/absmach/magistrala/sso:latest
  container_name: magistrala-sso
  ports:
    - ${MG_SSO_HTTP_PORT:-9030}:9030
  networks:
    - magistrala-base-net
  restart: on-failure:3
  environment:
    MG_SSO_LOG_LEVEL: ${MG_SSO_LOG_LEVEL:-info}
    MG_SSO_FRONTEND_URL: ${MG_SSO_FRONTEND_URL:-http://ui:3000}
    MG_SSO_INSTANCE_ID: ${MG_SSO_INSTANCE_ID}
    SMQ_USERS_URL: ${SMQ_USERS_URL:-http://ui:9002}
    SMQ_JAEGER_URL: ${SMQ_JAEGER_URL:-http://localhost:4318/v1/traces}
    SMQ_JAEGER_TRACE_RATIO: ${SMQ_JAEGER_TRACE_RATIO:-1.0}
    SMQ_SEND_TELEMETRY: ${SMQ_SEND_TELEMETRY:-true}
```

Add to `docker/.env`:

```bash
MG_SSO_LOG_LEVEL=info
MG_SSO_FRONTEND_URL=http://ui:3000
```

### 3. Build Docker Image

```bash
docker build --no-cache --build-arg SVC=sso --tag ghcr.io/absmach/magistrala/sso -f docker/Dockerfile .
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MG_SSO_LOG_LEVEL` | Log level (debug/info/warn/error) | `info` |
| `MG_SSO_FRONTEND_URL` | Frontend URL for redirect | `http://localhost:3000` |
| `MG_SSO_HTTP_PORT` | HTTP server port | `9030` |
| `SMQ_USERS_URL` | SuperMQ Users API URL | `http://users:9002` |
| `SMQ_JAEGER_URL` | Jaeger tracing URL | `http://localhost:4318/v1/traces` |
| `MG_SSO_INSTANCE_ID` | Service instance ID | auto-generated |

## Validation

### 1. Health Check

```bash
curl http://localhost:9030/health
```

Expected response:
```json
{"status":"pass"}
```

### 2. Metrics Check

```bash
curl http://localhost:9030/metrics | grep sso
```

Should see metrics like:
```
sso_requests_total{method="ProcessSSOCallback",status="failed"} 0
sso_requests_total{method="ProcessSSOCallback",status="success"} 0
sso_request_duration_seconds_bucket{method="ProcessSSOCallback"}
```

### 3. Create a Test SSO Token (for validation)

For testing only, create a valid JWT token:

```go
// Test token structure (base64url encoded)
// Header: {"alg":"RS256","typ":"JWT","kid":"test-key"}
// Payload: {"email":"test@example.com","name":"Test User","jti":"uuid-here","iss":"automax","iat":now,"exp":now+60,"nbf":now}
```

Use `https://jwt.io/` to create one manually for testing:

**Header**:
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

**Payload** (adjust `iat`, `exp`, `nbf` to current timestamps):
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "test@example.com",
  "name": "Test User",
  "jti": "550e8400-e29b-41d4-a716-446655440001",
  "iss": "automax",
  "iat": 1709500000,
  "nbf": 1709500000,
  "exp": 1709500060
}
```

**Note**: With `alg: "none"`, signature verification will be skipped (safe for).
This is useful for testing the flow without full RS256 verification.

### 4. Test SSO Callback

```bash
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJuYW1lIjoiVGVzdCBVXNlciIsImp0aSI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMSIsImlzcyI6ImF1dG9tYXgiLCJpYXQiOjE3MDk1MDAwMDAsIm5iZiI6MTcwOTUwMDAwMCwiZXhwIjoxNzA5NTAwMDYwfQ."

curl -v "http://localhost:9030/sso/callback?token=$TOKEN"
```

Expected: HTTP 302 redirect to `${MG_SSO_FRONTEND_URL}/dashboard` with tokens in query params.

### 5. Test with Invalid Token

```bash
curl -v "http://localhost:9030/sso/callback?token=invalid"
```

Expected: HTTP response with error message.

## Testing with External SSO (e.g., Auth0, Keycloak)

### 1. Configure External SSO

External SSO provider should redirect to:
```
https://your-sso-service/callback?token=<JWT>
```

### 2. Expected Flow

```
1. External SSO → Redirect to SSO service callback with JWT
2. SSO Service → Decode and validate JWT
3. SSO Service → Look up/Create user in SuperMQ
4. SSO Service → Issue SuperMQ tokens
5. SSO Service → Redirect to frontend with tokens
6. Frontend → Extract tokens from URL params
7. Frontend → Store tokens and redirect to dashboard
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
docker logs magistrala-sso

# Common issues:
# - Port 9030 already in use
# - Invalid environment variables
# - Missing dependencies
```

### No Response on Callback

```bash
# Check service health
curl http://localhost:9030/health

# Check metrics
curl http://localhost:9030/metrics

# Verify service is receiving requests by watching logs
docker logs -f magistrala-sso
```

### Token Validation Errors

The JWT token must have these claims:
- `sub`: User ID (UUID format)
- `email`: User email address
- `name`: User full name
- `jti`: Unique token ID (UUID format) - used for replay prevention
- `iss`: Issuer URL (or "automax")
- `iat`: Issued at timestamp
- `nbf`: Not valid before timestamp
- `exp`: Expiration timestamp

Token lifetime should be short (typically 60 seconds).

## Production Checklist

Before deploying to production:

- [ ] Implement RS256 signature verification with JWKS
- [ ] Implement FindUserByEmail using SuperMQ SDK
- [ ] Implement CreateUser using SuperMQ SDK
- [ ] Implement token issuance via SuperMQ Auth gRPC
- [ ] Add Redis for nonce replay attack prevention
- [ ] Configure HTTPS/TLS
- [ ] Set up proper logging and monitoring
- [ ] Test with your actual SSO provider
- [ ] Verify token expiry and replay protection works

See [IMPLEMENTATION.md](/home/user/sandbox/iot/magistrala/sso/IMPLEMENTATION.md) for detailed implementation guidance.
