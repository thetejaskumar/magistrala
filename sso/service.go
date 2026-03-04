// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sso

import (
	"context"
	"time"

	"github.com/absmach/supermq/pkg/errors"
)

var (
	// ErrSSOToken indicates error in SSO token processing
	ErrSSOToken = errors.NewAuthNError("failed to process SSO token")

	// ErrTokenExpired indicates the SSO token has expired
	ErrTokenExpired = errors.NewAuthNError("SSO token has expired")

	// ErrTokenInvalid indicates the SSO token is invalid
	ErrTokenInvalid = errors.NewAuthNError("SSO token signature verification failed")

	// ErrTokenAlreadyUsed indicates the SSO token nonce was already consumed (replay attack)
	ErrTokenAlreadyUsed = errors.NewAuthNError("SSO token has already been used")

	// ErrUserNotFound indicates user lookup failed
	ErrUserNotFound = errors.NewAuthNError("user not found")

	// ErrFailedToCreateUser indicates user creation failed
	ErrFailedToCreateUser = errors.New("failed to create user")

	// ErrFailedToIssueToken indicates token issuance failed
	ErrFailedToIssueToken = errors.NewAuthNError("failed to issue local token")

	// ErrMissingIssuer indicates issuer URL is missing from claims
	ErrMissingIssuer = errors.New("missing issuer in token claims")

	// ErrUnsupportedIssuer indicates issuer is not supported
	ErrUnsupportedIssuer = errors.New("unsupported issuer")
)

// SSOClaims represents the claims in an SSO JWT from the provider
type SSOClaims struct {
	// Sub is the user ID from the provider (UUID)
	Sub string `json:"sub"`

	// Email is the user's email address
	Email string `json:"email"`

	// Name is the user's full name
	Name string `json:"name"`

	// TargetApp is the name of the application link that was clicked
	TargetApp string `json:"target_app"`

	// Role is the user's primary role code (may be empty)
	Role string `json:"role"`

	// Jti is the unique token ID for one-time use (prevents replay attacks)
	Jti string `json:"jti"`

	// Iss is the issuer URL (e.g., https://automax.example.com)
	// If empty, defaults to "automax" for same-deployment SSO
	Iss string `json:"iss"`

	// Iat is the issued-at timestamp
	Iat int64 `json:"iat"`

	// Nbf is the not-valid-before timestamp
	Nbf int64 `json:"nbf"`

	// Exp is the expiration timestamp (typically 60 seconds after iat)
	Exp int64 `json:"exp"`
}

// SessionTokens represents the issued local tokens
type SessionTokens struct {
	// AccessToken is the issued local access token
	AccessToken string

	// RefreshToken is the issued local refresh token
	RefreshToken string

	// TokenExpiry is when the access token expires
	TokenExpiry time.Time
}

// Service specifies the SSO service interface
type Service interface {
	// ProcessSSOCallback processes the SSO callback.
	// It validates the SSO token, checks the nonce, looks up/creates the user,
	// and issues local tokens.
	//
	// Parameters:
	//   ctx - context
	//   token - the SSO JWT token string
	//   frontendURL - the base URL of the frontend for redirect
	//
	// Returns:
	//   - the redirect URL with local tokens
	//   - error if processing fails
	ProcessSSOCallback(ctx context.Context, token, frontendURL string) (string, error)
}
