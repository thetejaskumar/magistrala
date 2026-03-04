// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"

	"github.com/absmach/magistrala/sso"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/go-kit/kit/endpoint"
)

// callbackEndpoint processes the SSO callback request
func callbackEndpoint(svc sso.Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req := request.(ssoCallbackReq)

		// Get frontend URL from environment or use default
		// This is set in the main.go when creating the middleware
		frontendURL := ctx.Value("frontendURL").(string)
		if frontendURL == "" {
			return "", errors.New("frontend URL not configured")
		}

		// Process SSO callback
		redirectURL, err := svc.ProcessSSOCallback(ctx, req.token, frontendURL)
		if err != nil {
			return "", err
		}

		// Return the redirect URL for the HTTP response encoder to use
		return callbackRes{
			redirectURL: redirectURL,
		}, nil
	}
}
