# SSO Service Implementation Guide

This document describes the TODOs and placeholders in the SSO service that need to be implemented for production use.

## Overview

The SSO service provides Single Sign-On functionality by:
1. Verifying SSO JWT tokens from external identity providers
2. Looking up or creating users in the SuperMQ system
3. Issuing local SuperMQ tokens
4. Redirecting users back to the frontend with tokens

## Current Status

The codebase compiles and has proper structure, but contains placeholders that need production implementations.

## TODOs and Placeholders

### 1. Implement Full RS256 Signature Verification with JWKS

**File**: [`/home/user/sandbox/iot/magistrala/sso/middleware/jwt_verifier.go`](/home/user/sandbox/iot/magistrala/sso/middleware/jwt_verifier.go)

**Location**: Lines 123-132

**What needs to be done**:
The current implementation decodes JWTs and validates their structure, but does not fully verify the RS256 signature using JWKS.

**Implementation approach**:
```go
// In Verify() function, after extracting kid from header:
if issuerURL != "automax" && issuerURL != "" {
    fetcher := &JWKSFetcher{
        client:     v.httpClient,
        issuerKeys: v.issuerKeys,
        cacheTTL:   v.cacheExpiry,
        logger:     v.logger,
    }

    jwks, err := fetcher.FetchJWKS(ctx, issuerURL)
    if err != nil {
        return nil, errors.Wrap(sso.ErrTokenInvalid, err)
    }

    // Find key matching kid
    var jwk *JWK
    for _, key := range jwks.Keys {
        if key.Kid == kid {
            jwk = &key
            break
        }
    }

    if jwk == nil {
        return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("key not found for kid: %s", kid))
    }

    // Parse RSA public key
    pubKey, err := ParseRSAPublicKey(*jwk)
    if err != nil {
        return nil, errors.Wrap(sso.ErrTokenInvalid, err)
    }

    // Verify the signature
    if err := verifyRS256(parts, pubKey); err != nil {
        return nil, errors.Wrap(sso.ErrTokenInvalid, err)
    }
}
```

**Additional function needed**:
```go
func verifyRS256(parts []string, pubKey *rsa.PublicKey) error {
    signature, err := base64URLDecode(parts[2])
    if err != nil {
        return err
    }

    signingString := parts[0] + "." + parts[1]

    hasher := crypto.SHA256
    h := hasher.New()
    h.Write([]byte(signingString))

    return rsa.VerifyPKCS1v15(pubKey, hasher, h.Sum(nil), signature)
}
```

**Dependencies needed**:
```go
import (
    "crypto"
    "crypto/rsa"
)
```

### 2. Implement FindUserByEmail

**File**: [`/home/user/sandbox/iot/magistrala/cmd/sso/main.go`](/home/user/sandbox/iot/magistrala/cmd/sso/main.go)

**Location**: Lines 183-224

**What needs to be done**:
Implement user lookup via SuperMQ HTTP API to find a user by email.

**Implementation approach**:
1. Add SuperMQ SDK configuration to `config` struct for admin token
2. Create SDK client instance
3. Call `sdk.Users(ctx, PageMetadata{Email: email}, adminToken)`
4. Map response to `sso.User`
5. Return not found if no results

**Required configuration**:
```go
type config struct {
    // ... existing fields ...
    SuperMQAdminToken string `env:"SMQ_ADMIN_TOKEN" envDefault:""`
}
```

### 3. Implement CreateUser

**File**: [`/home/user/sandbox/iot/magistrala/cmd/sso/main.go`](/home/user/sandbox/iot/magistrala/cmd/sso/main.go)

**Location**: Lines 226-272

**What needs to be done**:
Implement user creation via SuperMQ HTTP API for SSO users.

**Implementation approach**:
1. Parse the user's full name into first/last name
2. Generate a temporary password (since user comes from SSO)
3. Call `sdk.CreateUser(ctx, user, adminToken)`
4. Map response to `sso.User`
5. Return created user with ID

**Considerations**:
- User should be marked as SSO authenticated
- User should have appropriate default role
- Consider adding AuthProvider field to indicate SSO origin

### 4. Implement Token Issuance

**File**: [`/home/user/sandbox/iot/magistrala/cmd/sso/main.go`](/home/user/sandbox/iot/magistrala/cmd/sso/main.go)

**Location**: Lines 278-308

**What needs to be done**:
Implement token issuance via SuperMQ Auth gRPC service.

**Implementation approach**:
1. Connect to SuperMQ Auth gRPC service using existing patterns
2. Call Auth.Login() or similar endpoint with user credentials
3. Extract access token, refresh token, and expiry from response
4. Return mapped `SessionTokens`

**Required configuration**:
```go
type config struct {
    // ... existing fields ...
    AuthGrpcURL string `env:"SMQ_AUTH_GRPC_URL" envDefault:"localhost:9010"`
}
```

**Example implementation**:
```go
import (
    "github.com/absmach/supermq/auth/api/grpc/auth"
    grpcAuthV1 "github.com/absmach/supermq/api/grpc/auth/v1"
    "github.com/absmach/supermq/pkg/grpcclient"
)

// In newService():
grpcCfg := grpcclient.Config{URL: cfg.AuthGrpcURL}
handler, err := grpcclient.NewHandler(grpcCfg)
// ... handle error ...

authClient := auth.NewAuthClient(handler.Conn, handler.Timeout)
```

### 5. Environment Variables

Add the following environment variables to your deployment:

| Variable | Description | Example |
|----------|-------------|---------|
| `SMQ_ADMIN_TOKEN` | SuperMQ admin token for user operations | `your-admin-token` |
| `SMQ_AUTH_GRPC_URL` | SuperMQ Auth gRPC URL | `auth:9010` |
| `SMQ_USERS_URL` | SuperMQ Users API URL | `users:9002` |

### 6. Nonce Replay Attack Prevention

**File**: [`/home/user/sandbox/iot/magistrala/sso/service_impl.go`](/home/user/sandbox/iot/magistrala/sso/service_impl.go)

**Status**: Currently not implemented

**What needs to be done**:
Add nonce tracking to prevent token replay attacks.

**Implementation approach**:
1. Add Redis client to service initialization
2. Before verifying nonce, check if it exists in Redis
3. If nonce exists, return `sso.ErrTokenAlreadyUsed`
4. If nonce is valid, store it with TTL matching token expiration
5. Consider adding a background cleanup

**Example**:
```go
import "github.com/redis/go-redis/v9"

type ssoService struct {
    // ... existing fields ...
    redisClient *redis.Client
}

func (s *ssoService) ProcessSSOCallback(ctx context.Context, token, frontendURL string) (string, error) {
    // ... after verifying claims ...

    // Check for replay attack
    nonceKey := NonceRedisKeyPrefix + claims.Jti
    exists, err := s.redisClient.Exists(ctx, nonceKey).Result()
    if err != nil {
        return "", err
    }
    if exists > 0 {
        return "", sso.ErrTokenAlreadyUsed
    }

    // Store nonce with TTL
    if err := s.redisClient.Set(ctx, nonceKey, "1", time.Duration(claims.Exp-now)*time.Second).Err(); err != nil {
        s.logger.Warn("failed to store nonce", "error", err)
    }

    // ... continue with processing ...
}
```

## Testing

After implementing the TODOs, verify:
1. Valid SSO tokens are accepted
2. Invalid/refused tokens are rejected
3. Users are created correctly
4. Existing users are found
5. Tokens are issued with correct expiry
6. Replay attacks are prevented
7. Metrics are exported correctly

## Related Files

- [API Transport](/home/user/sandbox/iot/magistrala/sso/api/transport.go) - HTTP endpoints
- [API Endpoint](/home/user/sandbox/iot/magistrala/sso/api/endpoint.go) - Business logic endpoints
- [Service](/home/user/sandbox/iot/magistrala/sso/service_impl.go) - Service implementation
- [JWT Verifier](/home/user/sandbox/iot/magistrala/sso/middleware/jwt_verifier.go) - Token verification
- [Logging Middleware](/home/user/sandbox/iot/magistrala/sso/middleware/logging.go) - Request logging
- [Metrics Middleware](/home/user/sandbox/iot/magistrala/sso/middleware/metrics.go) - Prometheus metrics
- [Tracing](/home/user/sandbox/iot/magistrala/sso/tracing/tracing.go) - OpenTelemetry tracing
- [Main](/home/user/sandbox/iot/magistrala/cmd/sso/main.go) - Service entry point
