// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package main contains the main function to start the SSO service.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	chclient "github.com/absmach/callhome/pkg/client"
	"github.com/absmach/magistrala/sso"
	ssoapi "github.com/absmach/magistrala/sso/api"
	"github.com/absmach/magistrala/sso/middleware"
	ssomiddleware "github.com/absmach/magistrala/sso/middleware"
	"github.com/absmach/magistrala/sso/tracing"
	"github.com/absmach/supermq"
	smqlog "github.com/absmach/supermq/logger"
	"github.com/absmach/supermq/pkg/jaeger"
	"github.com/absmach/supermq/pkg/server"
	httpserver "github.com/absmach/supermq/pkg/server/http"
	"github.com/absmach/supermq/pkg/uuid"
	"github.com/caarlos0/env/v11"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	svcName        = "sso"
	envPrefixHTTP  = "MG_SSO_HTTP_"
	defSvcHTTPPort = "9030" // SSO service port
)

type config struct {
	LogLevel        string `env:"MG_SSO_LOG_LEVEL" envDefault:"info"`
	FrontendURL     string `env:"MG_SSO_FRONTEND_URL" envDefault:"http://localhost:3000"`
	UsersURL        string `env:"SMQ_USERS_URL" envDefault:"http://users:9002"`
	JaegerURL       url.URL `env:"SMQ_JAEGER_URL" envDefault:"http://localhost:4318/v1/traces"`
	SendTelemetry   bool    `env:"SMQ_SEND_TELEMETRY" envDefault:"true"`
	InstanceID      string `env:"MG_SSO_INSTANCE_ID" envDefault:""`
	TraceRatio      float64 `env:"SMQ_JAEGER_TRACE_RATIO" envDefault:"1.0"`
	SpicedbHost     string `env:"SMQ_SPICEDB_HOST" envDefault:"localhost"`
	SpicedbPort     string `env:"SMQ_SPICEDB_PORT" envDefault:"50051"`
	SpicedbPreSharedKey string `env:"SMQ_SPICEDB_PRE_SHARED_KEY" envDefault:"12345678"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := smqlog.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf("failed to init logger: %s", err.Error())
	}

	var exitCode int
	defer smqlog.ExitWithError(&exitCode)

	if cfg.InstanceID == "" {
		idp := uuid.New()
		id, err := idp.ID()
		if err != nil {
			logger.Error(fmt.Sprintf("failed to generate instanceID: %s", err))
			exitCode = 1
			return
		}
		cfg.InstanceID = id
	}

	tp, err := jaeger.NewProvider(ctx, svcName, cfg.JaegerURL, cfg.InstanceID, cfg.TraceRatio)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to init Jaeger: %s", err))
		exitCode = 1
		return
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			logger.Error(fmt.Sprintf("error shutting down tracer provider: %v", err))
		}
	}()
	tracer := tp.Tracer(svcName)

	svc, err := newService(ctx, tracer, logger, cfg)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create %s service: %s", svcName, err))
		exitCode = 1
		return
	}

	httpServerConfig := server.Config{Port: defSvcHTTPPort}
	if err := env.ParseWithOptions(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s HTTP server configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	// Create a handler that injects frontendURL into context
	handlerWithFrontendURL := httpserver.NewServer(ctx, cancel, svcName, httpServerConfig,
		withFrontendURL(ssoapi.MakeHandler(svc, logger, cfg.InstanceID), cfg.FrontendURL),
		logger,
	)

	if cfg.SendTelemetry {
		chc := chclient.New(svcName, supermq.Version, logger, cancel)
		go chc.CallHome(ctx)
	}

	// Start servers
	g.Go(func() error {
		return handlerWithFrontendURL.Start()
	})

	g.Go(func() error {
		return server.StopSignalHandler(ctx, cancel, logger, svcName, handlerWithFrontendURL)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("SSO service terminated: %s", err))
	}
}

func newService(ctx context.Context, tracer trace.Tracer, logger *slog.Logger, cfg config) (sso.Service, error) {
	// Create SSO components
	usersClient := &smqUsersClient{
		usersURL: cfg.UsersURL,
		logger:   logger,
	}

	jwtVerifier := middleware.NewJWTVerifier(logger)
	tokenIssuer := &smqTokenIssuer{
		jwtVerifier: jwtVerifier,
		usersClient: usersClient,
		logger:      logger,
	}

	svc := sso.New(usersClient, jwtVerifier, tokenIssuer, logger)
	svc = ssomiddleware.NewLoggingMiddleware(logger, svc)

	// Create metrics counter and histogram for prometheus
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sso_requests_total",
			Help: "Total number of SSO requests",
		},
		[]string{"method", "status"},
	)
	latency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sso_request_duration_seconds",
			Help:    "SSO request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)
	// Register metrics
	prometheus.MustRegister(counter)
	prometheus.MustRegister(latency)

	svc = ssomiddleware.NewMetricsMiddleware(counter, latency, svc)
	svc = tracing.New(svc, tracer)

	return svc, nil
}

// smqUsersClient implements finding/creating users via SuperMQ SDK
type smqUsersClient struct {
	usersURL string
	logger   *slog.Logger
}

func (c *smqUsersClient) FindUserByEmail(ctx context.Context, email string) (sso.User, error) {
	// PRODUCTION NOTE:
	// This function should be implemented to call the SuperMQ Users API
	// to find a user by email address.
	//
	// Implementation approach:
	// 1. Create SuperMQ SDK client
	// 2. Call sdk.Users(ctx, PageMetadata{Email: email}, token) to search for user
	// 3. If user found, map to sso.User and return
	// 4. If not found, return sso.ErrUserNotFound
	//
	// Example code structure:
	//   cfg := sdk.Config{UsersURL: c.usersURL}
	//   sdk := sdk.NewSDK(cfg, nil)
	//   usersPage, err := sdk.Users(ctx, sdk.PageMetadata{Email: email}, c.adminToken)
	//   if err != nil { return sso.User{}, err }
	//   if usersPage.Total == 0 { return sso.User{}, sso.ErrUserNotFound }
	//   // Map first user in results to sso.User and return
	//
	return sso.User{}, fmt.Errorf("user not found: %s", email)
}

func (c *smqUsersClient) CreateUser(ctx context.Context, email, name string) (sso.User, error) {
	// PRODUCTION NOTE:
	// This function should be implemented to create a new user via SuperMQ Users API.
	//
	// Implementation approach:
	// 1. Parse name into first_name and last_name
	// 2. Create SuperMQ User struct with credentials
	// 3. Call sdk.CreateUser(ctx, user, adminToken)
	// 4. Map response to sso.User and return
	//
	// Example code structure:
	//   cfg := sdk.Config{UsersURL: c.usersURL}
	//   sdk := sdk.NewSDK(cfg, nil)
	//   firstName, lastName := parseName(name)
	//   user := sdk.User{
	//       Credentials: sdk.Credentials{Username: email, Secret: generatedPassword},
	//       FirstName: firstName,
	//       LastName: lastName,
	//       Email: email,
	//   }
	//   createdUser, err := sdk.CreateUser(ctx, user, c.adminToken)
	//   if err != nil { return sso.User{}, err }
	//   // Map createdUser to sso.User and return
	//
	idp := uuid.New()
	id, err := idp.ID()
	if err != nil {
		return sso.User{}, err
	}
	return sso.User{
		ID:       id,
		Email:    email,
		FullName: name,
		DomainID: "default-domain",
	}, nil
}

// parseName splits a full name into first and last name
func parseName(fullName string) (first, last string) {
	if fullName == "" {
		return "", ""
	}
	parts := strings.Split(fullName, " ")
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

// smqTokenIssuer implements issuing local tokens
type smqTokenIssuer struct {
	jwtVerifier sso.JWTVerifier
	usersClient sso.UsersClient
	logger      *slog.Logger
}

func (ti *smqTokenIssuer) Issue(ctx context.Context, user sso.User) (*sso.SessionTokens, error) {
	// PRODUCTION NOTE:
	// This function should be implemented to issue local tokens via SuperMQ Auth service.
	//
	// Implementation approach:
	// 1. Connect to SuperMQ Auth gRPC service
	// 2. Call Auth.Issue() with user credentials to generate tokens
	// 3. Extract access token, refresh token, and expiry from response
	// 4. Return mapped SessionTokens
	//
	// Example code structure using AuthNClient:
	//   grpcCfg := grpcclient.Config{}
	//   authClient := authsvc.NewAuthClient(connection)
	//   loginReq := &authn.AuthNReq{Identity: user.Email}
	//   response, err := authClient.Login(ctx, loginReq)
	//   if err != nil { return nil, err }
	//   return &sso.SessionTokens{
	//       AccessToken: response.GetAccessToken(),
	//       RefreshToken: response.GetRefreshToken(),
	//       TokenExpiry: time.Now().Add(expiry duration),
	//   }, nil
	//
	return &sso.SessionTokens{
		AccessToken:  "placeholder-access-token",
		RefreshToken: "placeholder-refresh-token",
		TokenExpiry:  time.Now().Add(24 * time.Hour),
	}, nil
}

// withFrontendURL wraps a handler to inject frontendURL into context
func withFrontendURL(next http.Handler, frontendURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "frontendURL", frontendURL)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
