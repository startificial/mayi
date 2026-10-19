package authorization_test

import (
	"context"
	"errors"
	"fmt"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/authorization"
	"strings"
	"testing"
	"time"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

type material struct {
	next int
	fail bool
}

func (m *material) NewAuthorizationMaterial(context.Context) (authorization.Material, error) {
	if m.fail {
		return authorization.Material{}, errors.New("entropy failed")
	}
	m.next++
	return authorization.Material{ID: fmt.Sprintf("id-%d", m.next), Secret: strings.Repeat(fmt.Sprint(m.next), 43), Hash: fmt.Sprintf("%064x", m.next)}, nil
}

type store struct {
	principal                                           authorization.Principal
	registration                                        domain.Registration
	workflow                                            domain.Transaction
	denied, recheckDenied, commitFailure, createFailure bool
	runs, loads, completions                            int
	pushed                                              domain.PushedRequest
	pushedLoads, pushedConsumptions                     int
	pushedAuthorized                                    bool
	inTransaction                                       bool
	objectGuard                                         *objectAuthority
}

func (s *store) AuthorizeConsent(_ context.Context, p authorization.AccessProof, _ time.Time) (authorization.Principal, error) {
	if s.denied {
		return authorization.Principal{}, authorization.ErrDenied
	}
	return s.principal, nil
}
func (s *store) RunAuthorization(ctx context.Context, _ grants.Scope, fn func(authorization.Transaction) error) error {
	s.runs++
	s.inTransaction = true
	defer func() { s.inTransaction = false }()
	candidate := *s
	candidate.pushedAuthorized = false
	if err := fn(&candidate); err != nil {
		s.loads += candidate.loads - s.loads
		s.pushedLoads += candidate.pushedLoads - s.pushedLoads
		return err
	}
	if s.commitFailure {
		return errors.New("commit failed")
	}
	*s = candidate
	return nil
}
func (s *store) Registration(context.Context, string, string) (domain.Registration, error) {
	return s.registration, nil
}
func (s *store) CreateAuthorization(_ context.Context, w domain.Transaction) error {
	if s.createFailure {
		return errors.New("create failed")
	}
	s.workflow = w
	return nil
}
func (s *store) Authorization(context.Context, string) (domain.Transaction, error) {
	s.loads++
	return s.workflow, nil
}
func (s *store) RecheckConsent(context.Context, authorization.AccessProof, authorization.Principal, time.Time) error {
	if s.recheckDenied {
		return authorization.ErrDenied
	}
	return nil
}
func (s *store) CompleteAuthorization(_ context.Context, w domain.Transaction, _ grants.Revision, _ time.Time) error {
	s.completions++
	s.workflow = w
	return nil
}
func setup(t *testing.T) (*authorization.Service, *store, *clock, *material, domain.Request, authorization.AccessProof) {
	t.Helper()
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	request := domain.Request{TenantIssuer: scope, ClientID: "web", RedirectURI: "https://app.example/cb", ResourceURI: "https://api.example", PKCEChallenge: strings.Repeat("A", 43), PermissionScopes: []string{"read"}}
	s := &store{principal: authorization.Principal{TenantIssuer: scope, SessionHash: strings.Repeat("a", 64), Subject: "user:alice"}, registration: domain.Registration{Client: clients.Client{ID: "web", Name: "Web", RedirectURIs: []string{request.RedirectURI}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}, AccessTokenSeconds: 300, Enabled: true}, Resource: resources.Resource{ID: "api", URI: request.ResourceURI, Name: "API", Scopes: []resources.Scope{{Name: "read", Description: "Read items"}}, AccessTokenSeconds: 300}, Policy: policy.Tenant{Version: 1, MaxAccessTokenSeconds: 600, MaxGrantSeconds: 3600}}}
	c := &clock{now: time.Unix(1700000000, 0)}
	m := &material{}
	service, _ := authorization.New(s, c, m, nil)
	browser := strings.Repeat("b", 64)
	if _, err := service.Begin(context.Background(), request, browser); err != nil {
		t.Fatal(err)
	}
	spec := s.workflow.Snapshot()
	proof := authorization.AccessProof{TenantIssuer: scope, SessionHash: s.principal.SessionHash, AuthorizationHash: spec.HandleHash, BrowserBindingHash: browser, CSRFHash: spec.CSRFHash}
	s.runs = 0
	return service, s, c, m, request, proof
}
func TestConsentRequiresAuthorizationBeforePayloadLoad(t *testing.T) {
	for _, mode := range []string{"anonymous", "foreign tenant", "session changed", "denied", "revoked before load", "invalid csrf"} {
		t.Run(mode, func(t *testing.T) {
			svc, s, _, _, _, p := setup(t)
			switch mode {
			case "anonymous":
				p.SessionHash = ""
			case "foreign tenant":
				s.principal.TenantIssuer.TenantID = "b"
			case "session changed":
				s.principal.SessionHash = strings.Repeat("d", 64)
			case "denied":
				s.denied = true
			case "revoked before load":
				s.recheckDenied = true
			case "invalid csrf":
				p.CSRFHash = ""
			}
			if _, err := svc.Decide(context.Background(), authorization.Decision{Approve: true, Proof: p}); !errors.Is(err, authorization.ErrDenied) {
				t.Fatal(err)
			}
			if s.loads != 0 || s.completions != 0 {
				t.Fatal("denial loaded protected payload or mutated", s.loads, s.completions)
			}
		})
	}
}
func TestConsentDisplaysAndApprovesExactSnapshot(t *testing.T) {
	svc, s, _, _, request, p := setup(t)
	view, err := svc.PrepareConsent(context.Background(), p)
	if err != nil || view.ClientName != "Web" || view.RedirectURI != request.RedirectURI || len(view.PermissionScopes) != 1 || view.PermissionScopes[0].Description != "Read items" {
		t.Fatal(view, err)
	}
	result, err := svc.Decide(context.Background(), authorization.Decision{Approve: true, Proof: p})
	if err != nil || result.Code == "" || result.RedirectURI != request.RedirectURI {
		t.Fatal(result, err)
	}
	if s.workflow.Snapshot().Status != domain.Approved || s.workflow.Snapshot().Subject != "user:alice" {
		t.Fatal("approval lost subject")
	}
	if result, err := svc.Decide(context.Background(), authorization.Decision{Approve: true, Proof: p}); err == nil || result.Code != "" {
		t.Fatal("approval replay returned code")
	}
}
func TestConsentFailuresNeverReturnAuthority(t *testing.T) {
	for _, mode := range []string{"expired", "policy changed", "redirect changed", "commit failed", "entropy failed"} {
		t.Run(mode, func(t *testing.T) {
			svc, s, c, m, _, p := setup(t)
			switch mode {
			case "expired":
				c.now = c.now.Add(5 * time.Minute)
			case "policy changed":
				s.registration.Policy.Version++
			case "redirect changed":
				s.registration.Client.RedirectURIs = []string{"https://other.example/cb"}
			case "commit failed":
				s.commitFailure = true
			case "entropy failed":
				m.fail = true
			}
			result, err := svc.Decide(context.Background(), authorization.Decision{Approve: true, Proof: p})
			if err == nil || result.Code != "" || result.RedirectURI != "" {
				t.Fatal("failure returned credential or redirect", result, err)
			}
		})
	}
}
func TestBeginFailureNeverReturnsHandles(t *testing.T) {
	svc, s, _, m, request, p := setup(t)
	for _, mode := range []string{"storage", "commit", "entropy", "invalid redirect"} {
		t.Run(mode, func(t *testing.T) {
			s.createFailure = mode == "storage"
			s.commitFailure = mode == "commit"
			m.fail = mode == "entropy"
			r := request
			if mode == "invalid redirect" {
				r.RedirectURI = "https://evil.example/cb"
			}
			result, err := svc.Begin(context.Background(), r, p.BrowserBindingHash)
			if err == nil || result.Handle != "" || result.CSRFToken != "" {
				t.Fatal("failed begin returned handle", result, err)
			}
		})
	}
}

func (s *store) BindConsentSession(_ context.Context, w domain.Transaction) error {
	if s.objectGuard != nil && !s.objectGuard.held {
		return authorization.ErrUnavailable
	}
	s.workflow = w
	return nil
}

func TestObjectAuthorityStaysClosedUntilPARAndConsentIntegration(t *testing.T) {
	svc, s, _, m, request, p := setup(t)
	objects, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: request.TenantIssuer, Resource: request.ResourceURI, Details: []grants.ObjectDetail{{Type: "https://api.example/types/file/v1", Identifier: "file:123", Actions: []string{"read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	request.ObjectCeiling = objects
	before := m.next
	if result, err := svc.Begin(context.Background(), request, p.BrowserBindingHash); !errors.Is(err, authorization.ErrInvalid) || result.Handle != "" || s.runs != 0 || m.next != before {
		t.Fatal("unsupported object begin reached storage or entropy", err)
	}
	spec := s.workflow.Snapshot()
	spec.Request = request
	s.workflow, err = domain.New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := svc.PrepareConsent(context.Background(), p); !errors.Is(err, authorization.ErrDenied) || result.ClientID != "" {
		t.Fatal("object metadata disclosed through scope-only consent", err)
	}
	if result, err := svc.Decide(context.Background(), authorization.Decision{Approve: true, Proof: p}); !errors.Is(err, authorization.ErrDenied) || result.Code != "" || s.completions != 0 || m.next != before {
		t.Fatal("scope-only consent approved object authority", err)
	}
}
