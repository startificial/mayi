package authorization

import (
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	"strings"
	"testing"
	"time"
)

func example() (Spec, Registration) {
	now := time.Unix(1700000000, 0)
	request := Request{TenantIssuer: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, ClientID: "web", RedirectURI: "https://app.example/cb?provider=mayi", ResourceURI: "https://api.example", PKCEChallenge: strings.Repeat("A", 43), PermissionScopes: []string{"read"}, State: "client-state"}
	spec := Spec{ID: "transaction-1", HandleHash: strings.Repeat("a", 64), BrowserBindingHash: strings.Repeat("b", 64), CSRFHash: strings.Repeat("c", 64), Request: request, PolicyVersion: 1, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), Status: Pending, ConsentSessionHash: strings.Repeat("e", 64)}
	current := Registration{Client: clients.Client{ID: "web", Name: "Web", RedirectURIs: []string{request.RedirectURI}, Resources: []string{"api"}, AccessTokenSeconds: 300, Enabled: true}, Resource: resources.Resource{ID: "api", URI: request.ResourceURI, Name: "API", Scopes: []resources.Scope{{Name: "read", Description: "Read items"}, {Name: "write", Description: "Write items"}}, AccessTokenSeconds: 300}, Policy: policy.Tenant{Version: 1, MaxAccessTokenSeconds: 600, MaxGrantSeconds: 3600}}
	return spec, current
}
func TestConsentPreservesExactRequestAndImmutableCeiling(t *testing.T) {
	spec, _ := example()
	workflow, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Request.PermissionScopes[0] = "write"
	if workflow.Snapshot().Request.PermissionScopes[0] != "read" {
		t.Fatal("request mutated through constructor alias")
	}
	snapshot := workflow.Snapshot()
	snapshot.Request.PermissionScopes[0] = "write"
	if workflow.Snapshot().Request.PermissionScopes[0] != "read" {
		t.Fatal("request mutated through snapshot alias")
	}
	approved, revision, err := workflow.Decide(true, "user:alice", "grant-1", strings.Repeat("d", 64), spec.CreatedAt.Add(time.Second), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Snapshot().Request.RedirectURI != spec.Request.RedirectURI || revision.Snapshot().Scopes[0] != "read" || revision.Snapshot().Number != 1 {
		t.Fatal("approval changed request authority")
	}
	for _, approve := range []bool{true, false} {
		if _, _, err := approved.Decide(approve, "user:alice", "other", strings.Repeat("e", 64), spec.CreatedAt.Add(2*time.Second), time.Hour); err == nil {
			t.Fatal("terminal decision changed")
		}
	}
	denied, _, err := workflow.Decide(false, "", "", "", spec.CreatedAt.Add(time.Second), time.Hour)
	if err != nil || denied.Snapshot().Status != Denied || denied.Snapshot().GrantID != "" {
		t.Fatal("denial created authority", err)
	}
}
func TestAuthorizationRejectsExpiryMalformedProofAndExpansion(t *testing.T) {
	spec, current := example()
	if !spec.Request.AllowedBy(current) {
		t.Fatal("valid registration refused")
	}
	for _, mode := range []string{"unregistered redirect", "wrong resource", "unknown permission", "disabled client", "binding required", "unapproved resource", "malformed PKCE", "empty permissions"} {
		t.Run(mode, func(t *testing.T) {
			s, c := example()
			switch mode {
			case "unregistered redirect":
				s.Request.RedirectURI = "https://app.example/cb?provider=evil"
			case "wrong resource":
				s.Request.ResourceURI = "https://other.example"
			case "unknown permission":
				s.Request.PermissionScopes = []string{"admin"}
			case "disabled client":
				c.Client.Enabled = false
			case "binding required":
				c.Policy.RequireBinding = true
			case "unapproved resource":
				c.Client.Resources = []string{"other"}
			case "malformed PKCE":
				s.Request.PKCEChallenge = strings.Repeat("B", 43)
			case "empty permissions":
				s.Request.PermissionScopes = nil
			}
			if s.Request.AllowedBy(c) {
				t.Fatal("invalid authority accepted")
			}
		})
	}
	workflow, _ := New(spec)
	for _, now := range []time.Time{spec.CreatedAt.Add(-time.Second), spec.ExpiresAt} {
		if _, _, err := workflow.Decide(true, "user:alice", "grant", strings.Repeat("d", 64), now, time.Hour); err == nil {
			t.Fatal("invalid approval time")
		}
	}
	spec.Status = Approved
	spec.Subject = "client:web"
	spec.GrantID = "grant"
	spec.CodeHash = strings.Repeat("d", 64)
	if _, err := New(spec); err == nil {
		t.Fatal("non-user subject rehydrated as user consent")
	}
}

func TestConsentSessionCannotChange(t *testing.T) {
	spec, _ := example()
	spec.ConsentSessionHash = ""
	workflow, _ := New(spec)
	bound, err := workflow.BindSession(strings.Repeat("e", 64), spec.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bound.BindSession(strings.Repeat("f", 64), spec.CreatedAt); err == nil {
		t.Fatal("consent transferred to another session")
	}
	if _, _, err := workflow.Decide(true, "user:alice", "grant", strings.Repeat("d", 64), spec.CreatedAt, time.Hour); err == nil {
		t.Fatal("unbound consent decided")
	}
}
