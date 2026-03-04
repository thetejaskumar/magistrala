// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sso

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/absmach/supermq/pkg/errors"
)

const (
	// MaxTokenTTL is the maximum allowed SSO token TTL (in seconds)
	// The provider typically uses 60s, but we allow a small buffer
	MaxTokenTTL = 90

	// NonceRedisKeyPrefix is the prefix for Redis keys storing SSO nonces
	NonceRedisKeyPrefix = "sso:nonce:"

	// NonceExpiry is the expiry time for nonces in Redis (in seconds)
	// We set this to token TTL + small buffer
	NonceExpiry = 65
)

// ssoService implements the SSO service interface
type ssoService struct {
	usersClient UsersClient
	jwtVerifier JWTVerifier
	logger      *slog.Logger
	tokenIssuerr TokenIssuer
}

// UsersClient provides methods for looking up and creating users
type UsersClient interface {
	// FindUserByEmail looks up a user by email address
	FindUserByEmail(ctx context.Context, email string) (User, error)

	// CreateUser creates a new user from SSO claims
	CreateUser(ctx context.Context, email, name string) (User, error)
}

// User represents a user in the system
type User struct {
	ID       string
	Email    string
	FullName string
	DomainID string
}

// JWTVerifier provides JWT verification capabilities
type JWTVerifier interface {
	// Verify verifies an RS256 JWT token and returns the claims
	Verify(ctx context.Context, token string) (*SSOClaims, error)
}

// TokenIssuer provides local token issuance capabilities
type TokenIssuer interface {
	// Issue issues local access and refresh tokens for a user
	Issue(ctx context.Context, user User) (*SessionTokens, error)
}

// New returns a new SSO service
func New(usersClient UsersClient, jwtVerifier JWTVerifier, tokenIssuerr TokenIssuer, logger *slog.Logger) Service {
	return &ssoService{
		usersClient:  usersClient,
		jwtVerifier:  jwtVerifier,
		logger:       logger,
		tokenIssuerr: tokenIssuerr,
	}
}

func (s *ssoService) ProcessSSOCallback(ctx context.Context, token, frontendURL string) (string, error) {
	s.logger.Debug("processing SSO callback")

	// Step 1: Verify the SSO token and extract claims
	claims, err := s.jwtVerifier.Verify(ctx, token)
	if err != nil {
		return "", errors.Wrap(ErrTokenInvalid, err)
	}

	s.logger.Debug("SSO token verified", "user_email", claims.Email, "iss", claims.Iss, "jti", claims.Jti)

	// Step 2: Check token expiration
	now := time.Now().Unix()
	if claims.Exp < now {
		s.logger.Warn("SSO token expired", "exp", claims.Exp, "now", now)
		return "", ErrTokenExpired
	}

	// Sanity check: make sure token wasn't issued too far in the future or past
	if now-claims.Iat > MaxTokenTTL {
		return "", ErrTokenInvalid
	}

	// Step 3: Look up or create user
	user, err := s.findOrCreateUser(ctx, claims)
	if err != nil {
		return "", errors.Wrap(ErrUserNotFound, err)
	}

	// Step 4: Issue local tokens
	tokens, err := s.tokenIssuerr.Issue(ctx, user)
	if err != nil {
		return "", errors.Wrap(ErrFailedToIssueToken, err)
	}

	s.logger.Info("SSO login successful", "user_id", user.ID, "user_email", user.Email)

	// Step 5: Build redirect URL with tokens
	redirectURL, err := s.buildRedirectURL(frontendURL, tokens)
	if err != nil {
		return "", errors.Wrap(ErrFailedToIssueToken, err)
	}

	return redirectURL, nil
}

// findOrCreateUser looks up a user by email or creates a new one
func (s *ssoService) findOrCreateUser(ctx context.Context, claims *SSOClaims) (User, error) {
	// Try to find existing user
	user, err := s.usersClient.FindUserByEmail(ctx, claims.Email)
	if err == nil {
		// User found, return it
		return user, nil
	}

	// User not found, create a new one
	s.logger.Info("user not found, creating new user", "email", claims.Email)
	user, err = s.usersClient.CreateUser(ctx, claims.Email, claims.Name)
	if err != nil {
		return User{}, errors.Wrap(ErrFailedToCreateUser, err)
	}

	return user, nil
}

// buildRedirectURL builds the redirect URL with tokens in query parameters
func (s *ssoService) buildRedirectURL(frontendURL string, tokens *SessionTokens) (string, error) {
	// Ensure frontendURL doesn't have trailing slash
	frontendURL = strings.TrimSuffix(frontendURL, "/")

	// Build the URL - redirecting to /dashboard directly
	redirectURL, err := url.Parse(frontendURL + "/dashboard")
	if err != nil {
		return "", fmt.Errorf("invalid frontend URL: %w", err)
	}

	// Add query parameters
	query := redirectURL.Query()
	query.Set("token", tokens.AccessToken)
	if tokens.RefreshToken != "" {
		query.Set("refresh", tokens.RefreshToken)
	}
	redirectURL.RawQuery = query.Encode()

	return redirectURL.String(), nil
}

// IsSameIssuer checks if the issuer is "automax" (string literal)
// Used for same-deployment SSO where iss is not a URL
func IsSameIssuer(iss string) bool {
	return iss == "automax" || iss == ""
}

// ExtractIssuerURL extracts the issuer URL from the iss claim
// Returns "automax" if iss is not a valid URL
func ExtractIssuerURL(iss string) string {
	if strings.HasPrefix(iss, "http://") || strings.HasPrefix(iss, "https://") {
		return strings.TrimSuffix(iss, "/")
	}
	return "automax"
}

// BuildJWKSURL builds the JWKS URL from an issuer URL
func BuildJWKSURL(issuerURL string) string {
	if issuerURL == "automax" || issuerURL == "" {
		return ""
	}
	return issuerURL + "/.well-known/jwks.json"
}

// HTTPFetcher provides HTTP request capabilities for fetching JWKS
type HTTPFetcher interface {
	// Get performs an HTTP GET request
	Get(url string) (*http.Response, error)
}
