package app

import (
	"context"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	"github.com/startificial/mayi/internal/adapters/inbound/http/selfservice"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/adapters/outbound/egress"
	upstream "github.com/startificial/mayi/internal/adapters/outbound/identity"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/services/authentication"
	grantservice "github.com/startificial/mayi/internal/services/grants"
	"net/http"
	"strings"
)

// NewBrowser composes the tenant browser routes independently of signing;
// login and consent do not sign access tokens. NewServer mounts the same handler.
func NewBrowser(ctx context.Context, c Config, t TenantConfig, store *postgres.Store, lookup func(string) string) (http.Handler, error) {
	p := t.IdentityProvider
	if p == nil || store == nil || lookup == nil {
		return nil, ErrConfiguration
	}
	if err := validateIdentityProvider(c, p); err != nil {
		return nil, err
	}
	scope, err := NewIssuerScope(c.PublicOrigin, t.ID)
	if err != nil {
		return nil, err
	}
	transport, err := egress.New(egress.Config{URLs: []string{strings.TrimSuffix(p.Issuer, "/") + "/.well-known/openid-configuration", p.TokenEndpoint, p.JWKSURI}, AllowLoopbackHTTP: c.AllowInsecureLoopback})
	if err != nil {
		return nil, ErrConfiguration
	}
	provider, err := upstream.New(ctx, upstream.Config{ID: p.ID, Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: lookup(p.ClientSecretEnv), RedirectURI: scope.Issuer + "/upstream/callback", AuthorizationEndpoint: p.AuthorizationEndpoint, TokenEndpoint: p.TokenEndpoint, JWKSURI: p.JWKSURI, SigningAlgorithm: p.SigningAlgorithm}, transport)
	if err != nil {
		return nil, ErrConfiguration
	}
	login, err := authentication.New(store, systemClock{}, cryptoadapter.NewLoginSecrets(), provider, scope)
	if err != nil {
		return nil, err
	}
	hash, err := credentialHasher(t, lookup)
	if err != nil {
		return nil, err
	}
	consent, err := newAuthorization(ctx, t, scope, store, hash)
	if err != nil {
		return nil, err
	}
	client, err := newClientAuthentication(c, scope, store, hash)
	if err != nil {
		return nil, err
	}
	pushed, err := oauth.NewPushed(scope, client, consent)
	if err != nil {
		return nil, err
	}
	browser, err := selfservice.New(login, consent, scope, p.Issuer)
	if err != nil {
		return nil, err
	}
	sessions, err := authentication.NewSessions(store, systemClock{}, scope)
	if err != nil {
		return nil, err
	}
	grants, err := grantservice.New(store, systemClock{}, scope)
	if err != nil {
		return nil, err
	}
	controls, err := selfservice.NewControls(sessions, grants, scope)
	if err != nil {
		return nil, err
	}
	router := http.NewServeMux()
	base := "/t/" + t.ID
	router.HandleFunc("POST "+base+"/par", pushed.Push)
	router.HandleFunc("GET "+base+"/authorize", browser.Authorize)
	router.HandleFunc("GET "+base+"/upstream/callback", browser.Callback)
	router.HandleFunc("GET "+base+"/consent", browser.Consent)
	router.HandleFunc("POST "+base+"/consent", browser.Decide)
	router.HandleFunc("POST "+base+"/session/end", browser.EndSession)
	router.HandleFunc("POST "+base+"/session/touch", controls.Touch)
	router.HandleFunc("GET "+base+"/sessions", controls.Sessions)
	router.HandleFunc("POST "+base+"/sessions/{id}/revoke", controls.Sessions)
	router.HandleFunc("GET "+base+"/grants", controls.Grants)
	router.HandleFunc("POST "+base+"/grants/{id}/revoke", controls.Grants)
	return router, nil
}
