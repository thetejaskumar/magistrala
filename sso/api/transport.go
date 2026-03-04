// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/absmach/magistrala/sso"
	"github.com/absmach/supermq"
	api "github.com/absmach/supermq/api/http"
	apiutil "github.com/absmach/supermq/api/http/util"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/go-chi/chi/v5"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	ssoCallbackPath = "/sso/callback"
	healthPath      = "/health"
	metricsPath     = "/metrics"
)

// MakeHandler returns a HTTP handler for SSO API endpoints.
func MakeHandler(svc sso.Service, logger *slog.Logger, instanceID string) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, api.EncodeError)),
	}

	r := chi.NewRouter()

	// SSO callback endpoint - handles GET with token query param
	r.Get(ssoCallbackPath, otelhttp.NewHandler(kithttp.NewServer(
		callbackEndpoint(svc),
		decodeCallbackRequest,
		encodeCallbackResponse,
		opts...,
	), "sso_callback").ServeHTTP)

	// Health endpoint
	r.Get(healthPath, supermq.Health("sso", instanceID))

	// Metrics endpoint
	r.Handle(metricsPath, promhttp.Handler())

	return r
}

// decodeCallbackRequest decodes the HTTP request into a ssoCallbackReq
func decodeCallbackRequest(_ context.Context, r *http.Request) (any, error) {
	req := ssoCallbackReq{
		token: r.URL.Query().Get("token"),
	}

	if err := req.validate(); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}

	return req, nil
}

// encodeCallbackResponse encodes the response
// Since we need to return a 302 redirect, we use a custom encoder
func encodeCallbackResponse(_ context.Context, w http.ResponseWriter, response any) error {
	res, ok := response.(callbackRes)
	if !ok {
		return errors.New("invalid response type")
	}

	// Return HTTP 302 redirect
	http.Redirect(w, nil /* r */, res.redirectURL, http.StatusFound)
	return nil
}

// callbackRes represents the callback response with redirect URL
type callbackRes struct {
	redirectURL string
}
