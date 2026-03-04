// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"time"

	"github.com/absmach/magistrala/sso"
	"github.com/prometheus/client_golang/prometheus"
)

var _ sso.Service = (*metricsMiddleware)(nil)

// metricsMiddleware is a metrics collecting middleware for SSO service
type metricsMiddleware struct {
	svc    sso.Service
	count  *prometheus.CounterVec
	latency *prometheus.HistogramVec
}

// NewMetricsMiddleware wraps the service with metrics
func NewMetricsMiddleware(counter *prometheus.CounterVec, latency *prometheus.HistogramVec, svc sso.Service) sso.Service {
	return &metricsMiddleware{
		svc:     svc,
		count:   counter,
		latency: latency,
	}
}

func (mm *metricsMiddleware) ProcessSSOCallback(ctx context.Context, token, frontendURL string) (string, error) {
	defer func(begin time.Time) {
		mm.latency.WithLabelValues("ProcessSSOCallback").Observe(time.Since(begin).Seconds())
	}(time.Now())

	result, err := mm.svc.ProcessSSOCallback(ctx, token, frontendURL)
	if err != nil {
		mm.count.WithLabelValues("ProcessSSOCallback", "failed").Inc()
	} else {
		mm.count.WithLabelValues("ProcessSSOCallback", "success").Inc()
	}
	return result, err
}
