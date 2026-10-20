package administration

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	"testing"
)

type registrationEffects struct {
	t                         *testing.T
	forbid, verified, allowed bool
	admissionErr              error
}

func (e *registrationEffects) InitialAccess(context.Context, grants.Scope, string) (bool, error) {
	if e.forbid {
		e.t.Fatal("credentials before scope admission")
	}
	return e.verified, nil
}
func (e *registrationEffects) NewClientID(context.Context, grants.Scope) (string, error) {
	if e.forbid {
		e.t.Fatal("material before admission")
	}
	return "agent-new", nil
}
func (e *registrationEffects) AdmitRegistration(context.Context, grants.Scope) (bool, error) {
	if e.forbid {
		e.t.Fatal("budget before trusted scope")
	}
	return e.allowed, e.admissionErr
}

func TestPublicRegistrationAdmissionPrecedesProtectedCatalog(t *testing.T) {
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	r := clients.PublicRegistration{Name: "Agent", RedirectURIs: []string{"https://agent.example/cb"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/item"}}
	for _, mode := range []string{"foreign", "invalid initial", "missing initial", "closed", "rate", "unavailable", "quota", "invalid metadata"} {
		t.Run(mode, func(t *testing.T) {
			f := &fake{t: t, forbidCatalog: true, registration: clients.RegistrationPolicy{Version: 1, Mode: "open", Resources: r.Resources, AuthorizationDetailsTypes: r.AuthorizationDetailsTypes, MaxClients: 1, AccessTokenSeconds: 120}}
			e := &registrationEffects{t: t, allowed: true}
			requested := scope
			credential := ""
			want := ErrDenied
			input := r
			switch mode {
			case "foreign":
				requested.TenantID = "b"
				e.forbid = true
				f.denyAccess = true
			case "invalid initial":
				credential = "bad"
				f.denyAccess = true
				want = ErrInitialAccess
			case "missing initial":
				f.registration.RequireInitialAccess = true
				want = ErrInitialAccess
			case "closed":
				f.registration = clients.RegistrationPolicy{Version: 1, Mode: "admin_only"}
			case "rate":
				e.allowed = false
				f.denyAccess = true
				want = ErrRegistrationLimited
			case "unavailable":
				e.admissionErr = ErrUnavailable
				f.denyAccess = true
				want = ErrUnavailable
			case "quota":
				f.dynamic = 1
				want = ErrRegistrationQuota
			case "invalid metadata":
				input.Resources = []string{"private"}
				want = ErrInvalid
			}
			s, _ := NewRegistration(f, e, e, scope)
			c, err := s.Register(context.Background(), requested, credential, input)
			if !errors.Is(err, want) || c.ID != "" || f.creates != 0 || f.audits != 0 {
				t.Fatal("registration admission failed", err)
			}
		})
	}
}

func TestRegistrationUsesSharedRulesAndWithholdsUncommittedResult(t *testing.T) {
	ctx := context.Background()
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	p := clients.RegistrationPolicy{Version: 1, Mode: "open", Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/item"}, MaxClients: 2, AccessTokenSeconds: 120}
	r := clients.PublicRegistration{Name: "Agent", RedirectURIs: []string{"https://agent.example/cb"}, Resources: p.Resources, AuthorizationDetailsTypes: p.AuthorizationDetailsTypes}
	profile, err := resources.NewObjectProfile(resources.ObjectProfileSpec{Scope: scope, Resource: "https://api.example", Type: p.AuthorizationDetailsTypes[0], Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read items"}}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{t: t, p: policy.Tenant{Version: 1, MaxAccessTokenSeconds: 300, MaxGrantSeconds: 3600}, registration: p, profile: profile, resource: resources.Resource{ID: "api", URI: "https://api.example", AccessTokenSeconds: 300}}
	e := &registrationEffects{t: t, allowed: true, verified: true}
	s, _ := NewRegistration(f, e, e, scope)
	c, err := s.Register(ctx, scope, "", r)
	if err != nil || c.ID == "" || !c.RequireBinding || f.audits != 1 || f.dynamic != 1 {
		t.Fatal("registration failed", err)
	}
	f.commitErr = ErrUnavailable
	c, err = s.Register(ctx, scope, "", r)
	if !errors.Is(err, ErrUnavailable) || c.ID != "" {
		t.Fatal("uncommitted client escaped")
	}
	f.denyAccess = true
	management, _ := New(f, f, f)
	foreign := Actor{ID: "admin", Scope: grants.Scope{TenantID: "b", Issuer: "https://auth.example/t/b"}, Permissions: []string{"clients:read", "clients:write"}}
	if _, err := management.RegistrationPolicy(ctx, foreign, scope); !errors.Is(err, ErrDenied) {
		t.Fatal("foreign read")
	}
	if _, err := management.SetRegistrationPolicy(ctx, foreign, scope, p); !errors.Is(err, ErrDenied) {
		t.Fatal("foreign mutation")
	}
}
