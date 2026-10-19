// Package app is the reference application's composition root.
package app

import (
	"github.com/startificial/mayi/examples/bff/adapters/api"
	cryptoadapter "github.com/startificial/mayi/examples/bff/adapters/crypto"
	transport "github.com/startificial/mayi/examples/bff/adapters/http"
	"github.com/startificial/mayi/examples/bff/adapters/memory"
	"github.com/startificial/mayi/examples/bff/adapters/oauth"
	"github.com/startificial/mayi/examples/bff/services"
	"net/http"
	"time"
)

type Config struct {
	Tenant, Issuer, Resource, Client, Secret, Origin, ObjectType string
	Keys                                                         []cryptoadapter.Key
}
type clock struct{}

func (clock) Now() time.Time { return time.Now() }
func New(c Config) (http.Handler, error) {
	cipher, err := cryptoadapter.New(c.Keys)
	if err != nil {
		return nil, err
	}
	// All destinations come from operator configuration. Disable environment proxy
	// routing and redirects so credentials cannot follow an API-controlled Location.
	wire := http.DefaultTransport.(*http.Transport).Clone()
	wire.Proxy = nil
	httpClient := &http.Client{Transport: wire, Timeout: 5 * time.Second}
	client, err := oauth.New(c.Issuer, c.Client, c.Secret, c.Origin+"/callback", c.Resource, httpClient)
	if err != nil {
		return nil, err
	}
	apiClient, err := api.New(c.Resource, httpClient)
	if err != nil {
		return nil, err
	}
	store := memory.New()
	sessions, err := services.New(store, cipher, client, apiClient, clock{}, services.CredentialContext{Tenant: c.Tenant, Issuer: c.Issuer, Client: c.Client, Resource: c.Resource})
	if err != nil {
		return nil, err
	}
	login, err := services.NewLogin(sessions, store, cipher, client, cryptoadapter.NewLoginSource(), clock{}, services.AuthorizationRequest{Type: c.ObjectType, Identifier: "123", Permission: "read", Actions: []string{"read"}})
	if err != nil {
		return nil, err
	}
	handler, err := transport.New(sessions, login, c.Origin)
	if err != nil {
		return nil, err
	}
	return handler.Routes(), nil
}
