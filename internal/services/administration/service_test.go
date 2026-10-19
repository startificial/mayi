package administration

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	"testing"
	"time"
)

type fake struct {
	t               *testing.T
	denyAccess      bool
	p               policy.Tenant
	audits, creates int
	commitErr       error
	resource        resources.Resource
	profile         resources.ObjectProfile
}

func (f *fake) RunManagement(_ context.Context, _ grants.Scope, fn func(Transaction) error) error {
	if f.denyAccess {
		f.t.Fatal("storage accessed before authorization")
	}
	if err := fn(f); err != nil {
		return err
	}
	return f.commitErr
}
func (f *fake) ProvisionTenant(context.Context, grants.Scope, identity.PublicKey, policy.Tenant, string) error {
	if f.denyAccess {
		f.t.Fatal("provisioning before authorization")
	}
	return nil
}
func (f *fake) Policy(context.Context) (policy.Tenant, error)      { return f.p, nil }
func (f *fake) SetPolicy(_ context.Context, p policy.Tenant) error { f.p = p; return nil }
func (f *fake) Resource(context.Context, string) (resources.Resource, error) {
	if f.resource.URI != "" {
		return f.resource, nil
	}
	return resources.Resource{AccessTokenSeconds: 300}, nil
}
func (f *fake) RegisterObjectProfile(_ context.Context, _ string, p resources.ObjectProfile) error {
	f.creates++
	f.profile = p
	return nil
}
func (f *fake) ObjectProfile(context.Context, string, string) (resources.ObjectProfile, error) {
	return f.profile, nil
}
func (f *fake) CreateResource(context.Context, resources.Resource) error         { f.creates++; return nil }
func (f *fake) Client(context.Context, string) (clients.Client, error)           { return clients.Client{}, nil }
func (f *fake) CreateClient(context.Context, clients.Client) error               { f.creates++; return nil }
func (f *fake) PublishKey(context.Context, identity.PublicKey, time.Time) error  { return nil }
func (f *fake) ActivateKey(context.Context, int, time.Time, time.Duration) error { return nil }
func (f *fake) Audit(context.Context, string, string, string) error              { f.audits++; return nil }
func (f *fake) PublicKey(context.Context, grants.Scope, int) (identity.PublicKey, error) {
	if f.denyAccess {
		f.t.Fatal("key loaded before authorization")
	}
	return identity.PublicKey{}, nil
}
func (f *fake) Now() time.Time { return time.Unix(100, 0) }
func TestEveryManagementOperationAuthorizesBeforeProtectedAccess(t *testing.T) {
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	for _, mode := range []string{"anonymous", "foreign tenant", "missing permission", "wrong issuer"} {
		t.Run(mode, func(t *testing.T) {
			f := &fake{t: t, denyAccess: true}
			s, _ := New(f, f, f)
			actor := Actor{ID: "admin", Scope: scope, Permissions: []string{"policy:read", "policy:write", "resources:read", "resources:write", "clients:read", "clients:write", "keys:write"}}
			switch mode {
			case "anonymous":
				actor = Actor{}
			case "foreign tenant":
				actor.Scope.TenantID = "b"
			case "wrong issuer":
				actor.Scope.Issuer = "https://evil.example/t/a"
			case "missing permission":
				actor.Permissions = nil
			}
			_, e1 := s.Policy(context.Background(), actor, scope)
			_, e2 := s.SetPolicy(context.Background(), actor, scope, policy.Tenant{})
			e3 := s.CreateResource(context.Background(), actor, scope, resources.Resource{})
			_, e4 := s.Resource(context.Background(), actor, scope, "x")
			e5 := s.CreateClient(context.Background(), actor, scope, clients.Client{})
			_, e6 := s.Client(context.Background(), actor, scope, "x")
			e7 := s.PublishKey(context.Background(), actor, scope, 1)
			e8 := s.ActivateKey(context.Background(), actor, scope, 1)
			e9 := s.ProvisionTenant(context.Background(), actor, scope, 1)
			e10 := s.RegisterObjectProfile(context.Background(), actor, scope, "api", resources.ObjectProfileSpec{})
			_, e11 := s.ObjectProfile(context.Background(), actor, scope, "api", "https://api.example/types/workflow/v1")
			for _, err := range []error{e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11} {
				if !errors.Is(err, ErrDenied) {
					t.Fatal("unauthorized operation did not deny")
				}
			}
		})
	}
}
func TestPolicyVersionCeilingsAndAtomicResult(t *testing.T) {
	f := &fake{t: t, p: policy.Tenant{Version: 3, MaxAccessTokenSeconds: 300, MaxGrantSeconds: 3600, RequireBinding: true}}
	s, _ := New(f, f, f)
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	actor := Actor{ID: "admin", Scope: scope, Permissions: []string{"policy:write", "resources:write", "clients:write"}}
	input := resources.Resource{ID: "api", URI: "https://api.example", Name: "API", Scopes: []resources.Scope{{Name: "read", Description: "Read items"}}, AccessTokenSeconds: 600, RequireBinding: true}
	if err := s.CreateResource(context.Background(), actor, scope, input); !errors.Is(err, ErrInvalid) || f.creates != 0 {
		t.Fatal("resource exceeded policy")
	}
	input.AccessTokenSeconds = 300
	input.RequireBinding = false
	if err := s.CreateResource(context.Background(), actor, scope, input); !errors.Is(err, ErrInvalid) {
		t.Fatal("binding policy downgraded")
	}
	input.RequireBinding = true
	if err := s.CreateResource(context.Background(), actor, scope, input); err != nil || f.audits != 1 {
		t.Fatal("valid resource not audited", err)
	}
	p := f.p
	p.Version = 2
	if _, err := s.SetPolicy(context.Background(), actor, scope, p); !errors.Is(err, ErrConflict) {
		t.Fatal("stale policy replaced current state")
	}
	p.Version = 3
	f.commitErr = ErrUnavailable
	if result, err := s.SetPolicy(context.Background(), actor, scope, p); err == nil || result.Version != 0 {
		t.Fatal("uncommitted result escaped")
	}
}
