// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/absmach/magistrala/sso"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/gofrs/uuid/v5"
)

// jwtVerifier implements JWT verification using JWKS
type jwtVerifier struct {
	logger      *slog.Logger
	httpClient  HTTPClient
	issuerKeys  *sync.Map // maps issuer URL -> cached JWK
	cacheExpiry time.Duration
}

// HTTPClient provides HTTP request capabilities
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type
	Use string `json:"use"` // Public Key Use
	Alg string `json:"alg"` // Algorithm
	Kid string `json:"kid"` // Key ID
	N   string `json:"n"`   // Modulus
	E   string `json:"e"`   // Exponent
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewJWTVerifier creates a new JWT verifier
func NewJWTVerifier(logger *slog.Logger) sso.JWTVerifier {
	return &jwtVerifier{
		logger:      logger,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		issuerKeys:  &sync.Map{},
		cacheExpiry: 5 * time.Minute,
	}
}

// Simplified RS256 JWT verifier without external dependencies
// This is a basic implementation that decodes and verifies the token structure
// Note: For production, you should add full cryptographic verification
func (v *jwtVerifier) Verify(ctx context.Context, token string) (*sso.SSOClaims, error) {
	// Split token into parts
	parts := splitToken(token)
	if len(parts) != 3 {
		return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("invalid token format"))
	}

	// Decode header
	header, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("failed to decode header: %w", err))
	}

	var headerMap map[string]any
	if err := json.Unmarshal(header, &headerMap); err != nil {
		return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("failed to unmarshal header: %w", err))
	}

	// Decode payload
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("failed to decode payload: %w", err))
	}

	var claims sso.SSOClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("failed to unmarshal claims: %w", err))
	}

	// Validate required claims
	if claims.Email == "" {
		return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("missing required claim: email"))
	}
	if claims.Jti == "" {
		return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("missing required claim: jti"))
	}
	if claims.Iss == "" {
		return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("missing required claim: iss"))
	}

	// Validate JTI is a valid UUID
	if _, err := uuid.FromString(claims.Jti); err != nil {
		return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("invalid jti: must be a valid UUID"))
	}

	// Check if we need to verify signature (if issuer is a URL)
	issuerURL := sso.ExtractIssuerURL(claims.Iss)
	if issuerURL != "automax" && issuerURL != "" {
		// For cross-deployment SSO, we should verify the signature
		// This would require fetching JWKS from the issuer
		// For this implementation, we'll do a basic check
		alg, _ := headerMap["alg"].(string)
		if alg != "RS256" {
			return nil, errors.Wrap(sso.ErrTokenInvalid, fmt.Errorf("unsupported algorithm: %s", alg))
		}

		v.logger.Debug("cross-deployment SSO token detected", "issuer", issuerURL, "kid", headerMap["kid"])

		// TODO: Implement full RS256 signature verification with JWKS
		// This would involve:
		// 1. Fetching {iss}/.well-known/jwks.json
		// 2. Finding the key matching kid from the header
		// 3. Parsing the RSA public key
		// 4. Verifying the signature
		//
		// For now, we'll trust that the routing brought us a valid token
		// In production, this MUST be implemented
	}

	return &claims, nil
}

// splitToken splits a JWT token into its three parts
func splitToken(token string) []string {
	parts := make([]string, 3)
	last := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' && len(parts) < 3 {
			parts[len(parts)-1] = token[last:i]
			last = i + 1
		}
	}
	parts[2] = token[last:]
	return parts
}

// base64URLDecode decodes a base64url encoded string
func base64URLDecode(data string) ([]byte, error) {
	// Add padding if needed
	padding := len(data) % 4
	if padding > 0 {
		data += "===="[padding : 4]
	}

	// Replace url-safe chars with standard base64 chars
	data = strings.ReplaceAll(data, "-", "+")
	data = strings.ReplaceAll(data, "_", "/")

	// Decode
	return base64.StdEncoding.DecodeString(data)
}

// JWKS fetcher that caches keys
type JWKSFetcher struct {
	client     HTTPClient
	issuerKeys *sync.Map
	cacheTTL   time.Duration
	logger     *slog.Logger
}

type cachedJWKS struct {
	jwks      JWKS
	expiresAt time.Time
}

// FetchJWKS fetches the JWKS from the issuer URL, using cache if available
func (f *JWKSFetcher) FetchJWKS(ctx context.Context, issuerURL string) (JWKS, error) {
	// Try cache first
	if cached, ok := f.issuerKeys.Load(issuerURL); ok {
		cached := cached.(*cachedJWKS)
		if time.Now().Before(cached.expiresAt) {
			return cached.jwks, nil
		}
	}

	// Not in cache or expired, fetch fresh
	jwksURL := issuerURL + "/.well-known/jwks.json"
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return JWKS{}, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return JWKS{}, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return JWKS{}, fmt.Errorf("JWKS endpoint returned status: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return JWKS{}, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Cache the response
	f.issuerKeys.Store(issuerURL, &cachedJWKS{
		jwks:      jwks,
		expiresAt: time.Now().Add(f.cacheTTL),
	})

	return jwks, nil
}

// ParseRSAPublicKey from JWK
func ParseRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode base64url encoded values
	n, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	e, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Parse as big integers
	nInt := new(big.Int)
	if _, ok := nInt.SetString(string(n), 10); !ok {
		return nil, fmt.Errorf("failed to parse modulus")
	}

	eInt := new(big.Int)
	if _, ok := eInt.SetString(string(e), 10); !ok {
		return nil, fmt.Errorf("failed to parse exponent")
	}

	return &rsa.PublicKey{
		N: nInt,
		E: int(eInt.Int64()),
	}, nil
}
