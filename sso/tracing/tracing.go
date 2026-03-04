// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"

	"github.com/absmach/magistrala/sso"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

var _ sso.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	svc    sso.Service
	tracer trace.Tracer
}

// New returns a new tracing middleware that traces SSO service operations.
func New(svc sso.Service, tracer trace.Tracer) sso.Service {
	return &tracingMiddleware{
		svc:    svc,
		tracer: tracer,
	}
}

func (tm *tracingMiddleware) ProcessSSOCallback(ctx context.Context, token, frontendURL string) (string, error) {
	ctx, span := otel.Tracer("sso").Start(ctx, "ProcessSSOCallback",
		trace.WithAttributes(
			// Add attributes here if needed
		),
	)
	defer span.End()

	return tm.svc.ProcessSSOCallback(ctx, token, frontendURL)
}
