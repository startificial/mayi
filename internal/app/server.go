package app

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/adapters/inbound/http/admin"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oidc"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/adapters/outbound/signing"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/discovery"
	"github.com/startificial/mayi/internal/services/health"
	"log/slog"
	"net/http"
	"time"
)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func newRing(ctx context.Context, c Config, t TenantConfig, store *postgres.Store, lookup func(string) string) (*signing.Ring, error) {
	scope, err := NewIssuerScope(c.PublicOrigin, t.ID)
	if err != nil {
		return nil, err
	}
	var versions []*signing.Transit
	for _, version := range t.KeyVersions {
		s, err := signing.New(ctx, signing.Config{Address: c.TransitAddress, Key: t.KeyName, Token: lookup(t.TransitTokenEnv), Version: version, Scope: scope, AllowLoopbackHTTP: c.AllowInsecureLoopback}, &http.Client{Timeout: 3 * time.Second})
		if err != nil {
			return nil, err
		}
		versions = append(versions, s)
	}
	return signing.NewRing(scope, versions, store)
}

// NewServer wires concrete adapters; request handlers never receive a pool.
func NewServer(ctx context.Context, c Config, pool *pgxpool.Pool, lookup func(string) string, logger *slog.Logger) (*http.Server, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if pool == nil || lookup == nil || logger == nil {
		return nil, ErrConfiguration
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return nil, ErrConfiguration
	}
	err = postgres.ValidateRuntime(ctx, connection.Conn(), c.RuntimeRole)
	connection.Release()
	if err != nil {
		return nil, err
	}
	store, err := postgres.New(pool)
	if err != nil {
		return nil, err
	}
	discoveryService, err := discovery.New(store)
	if err != nil {
		return nil, err
	}
	router := http.NewServeMux()
	var credentials []middleware.Credential
	for _, t := range c.Tenants {
		scope, _ := NewIssuerScope(c.PublicOrigin, t.ID)
		for _, a := range t.Administrators {
			credentials = append(credentials, middleware.Credential{SHA256: a.TokenSHA256, Actor: administration.Actor{ID: a.ID, Scope: scope, Permissions: a.Permissions}})
		}
	}
	auth, err := middleware.New(credentials)
	if err != nil {
		return nil, err
	}
	rings := map[grants.Scope]*signing.Ring{}
	for _, t := range c.Tenants {
		scope, _ := NewIssuerScope(c.PublicOrigin, t.ID)
		ring, err := newRing(ctx, c, t, store, lookup)
		if err != nil {
			return nil, err
		}
		active, err := store.ActiveSigningKey(ctx, scope)
		if err != nil {
			return nil, err
		}
		if err := ring.Check(ctx, scope, active); err != nil {
			return nil, err
		}
		published, err := store.PublishedKeys(ctx, scope)
		if err != nil || len(published) == 0 {
			return nil, ErrConfiguration
		}
		for _, key := range published {
			loaded, err := ring.PublicKey(ctx, scope, key.Version)
			if err == nil && loaded != key {
				return nil, ErrConfiguration
			}
		}
		rings[scope] = ring
		service, err := administration.New(store, ring, systemClock{})
		if err != nil {
			return nil, err
		}
		h, err := admin.New(service, scope)
		if err != nil {
			return nil, err
		}
		public, err := oidc.New(discoveryService, scope)
		if err != nil {
			return nil, err
		}
		base := "/admin/t/" + t.ID
		for pattern, handler := range map[string]http.HandlerFunc{
			"GET " + base + "/policy": h.Policy, "PUT " + base + "/policy": h.Policy,
			"POST " + base + "/resources": h.CreateResource, "GET " + base + "/resources/{id}": h.Resource,
			"POST " + base + "/resources/{id}/object-profiles": h.RegisterObjectProfile,
			"GET " + base + "/resources/{id}/object-profiles":  h.ObjectProfile,
			"POST " + base + "/clients":                        h.CreateClient, "GET " + base + "/clients/{id}": h.Client,
			"POST " + base + "/keys/{version}/publish": h.PublishKey, "POST " + base + "/keys/{version}/activate": h.ActivateKey,
		} {
			router.Handle(pattern, auth.Protect(scope, handler))
		}
		router.HandleFunc("GET /.well-known/oauth-authorization-server/t/"+t.ID, public.Metadata)
		router.HandleFunc("GET /t/"+t.ID+"/jwks", public.JWKS)
		if t.IdentityProvider != nil {
			browser, err := NewBrowser(ctx, c, t, store, lookup)
			if err != nil {
				return nil, err
			}
			router.Handle("/t/"+t.ID+"/", browser)
		}
	}
	telemetry := middleware.NewTelemetry(logger)
	signers := make([]health.TenantSigner, 0, len(rings))
	for scope, ring := range rings {
		signers = append(signers, health.TenantSigner{Scope: scope, Signer: ring})
	}
	readiness, err := health.New(store, store, signers)
	if err != nil {
		return nil, err
	}
	router.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httptransport.JSON(w, 200, struct {
			Status string `json:"status"`
		}{"ok"})
	})
	router.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := readiness.Ready(ctx); err != nil {
			httptransport.Error(w, 503, "not_ready")
			return
		}
		httptransport.JSON(w, 200, struct {
			Status string `json:"status"`
		}{"ready"})
	})
	router.HandleFunc("GET /metrics", telemetry.Metrics)
	// Liveness is independent of public admission and dependency readiness.
	// Match the exact operation before choosing the wrapper; every other route
	// retains the public concurrency bound and request timeout.
	publicHandler := telemetry.Wrap(http.TimeoutHandler(router, 10*time.Second, `{"error":"temporarily_unavailable"}`))
	liveness := telemetry.Observe(router)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/healthz" {
			liveness.ServeHTTP(w, r)
			return
		}
		publicHandler.ServeHTTP(w, r)
	})
	return &http.Server{Addr: c.ListenAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)}, nil
}
