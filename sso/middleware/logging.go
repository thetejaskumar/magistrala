// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"log/slog"
	"time"

	"github.com/absmach/magistrala/sso"
)

var _ sso.Service = (*loggingMiddleware)(nil)

// loggingMiddleware is a logging middleware for SSO service
type loggingMiddleware struct {
	logger *slog.Logger
	svc    sso.Service
}

// NewLoggingMiddleware wraps the service with logging
func NewLoggingMiddleware(logger *slog.Logger, svc sso.Service) sso.Service {
	return &loggingMiddleware{
		logger: logger,
		svc:    svc,
	}
}

func (lm *loggingMiddleware) ProcessSSOCallback(ctx context.Context, token, frontendURL string) (string, error) {
	defer func(begin time.Time) {
		lm.logger.DebugContext(ctx,
			"ProcessSSOCallback completed",
			"duration", time.Since(begin),
		)
	}(time.Now())

	return lm.svc.ProcessSSOCallback(ctx, token, frontendURL)
}
