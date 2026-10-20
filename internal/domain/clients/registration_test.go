package clients

import "testing"

func TestPublicRegistrationCannotEnlargeTenantCeilings(t *testing.T) {
	p := RegistrationPolicy{Version: 1, Mode: "open", Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/item"}, MaxClients: 10, AccessTokenSeconds: 120}
	r := PublicRegistration{Name: "Agent", RedirectURIs: []string{"https://agent.example/callback"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/item"}}
	c, ok := p.Client("agent", r)
	if !ok || !c.Valid() || !c.RequireBinding || c.AuthMethod != "none" || c.Machine || c.Introspection {
		t.Fatal("unsafe public registration")
	}
	r.Resources[0] = "other"
	if c.Resources[0] != "api" {
		t.Fatal("mutable registration escaped")
	}
	if _, ok := p.Client("agent", r); ok {
		t.Fatal("foreign resource admitted")
	}
	r.Resources[0] = "api"
	r.AuthorizationDetailsTypes = []string{"https://api.example/types/private"}
	if _, ok := p.Client("agent", r); ok {
		t.Fatal("unapproved vocabulary admitted")
	}
	for _, mode := range []string{"", "admin_only", "approved_hosts", "OPEN"} {
		p.Mode = mode
		if _, ok := p.Client("agent", r); ok {
			t.Fatal("unknown/closed mode admitted")
		}
	}
	p.Mode = "open"
	p.MaxClients = 0
	if p.Valid() {
		t.Fatal("unbounded quota accepted")
	}
}
