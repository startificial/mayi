package contract_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/startificial/mayi/internal/domain/grants"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/delegation"
)

type exchangePolicy struct {
	deny bool
	edge delegation.Edge
}

func (p exchangePolicy) AuthorizeExchange(context.Context, delegation.Command) (delegation.Edge, error) {
	if p.deny {
		return delegation.Edge{}, errors.New("denied")
	}
	return p.edge, nil
}

type exchangeSubject struct {
	value delegation.Subject
	reads int
}

func (s *exchangeSubject) ReadSubject(context.Context, grants.Scope, string) (delegation.Subject, error) {
	s.reads++
	return s.value, nil
}
func TestRecipientExchangePlanningHookAndDenialOrder(t *testing.T) {
	now := time.Now()
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	parent := domain.AccessClaims{ID: "parent", Scope: scope, GrantID: "root", Revision: 7, Subject: "user:alice", PrincipalType: "user", Resource: "https://gateway.example", Scopes: []string{"read", "write"}, ExpiresAt: now.Add(time.Minute)}
	edge := delegation.Edge{Scope: scope, RecipientClientID: "gateway-client", SourceResource: parent.Resource, TargetResource: "https://downstream.example", Scopes: []string{"read"}, Lifetime: 5 * time.Minute}
	cmd := delegation.Command{Scope: scope, CallerClientID: "gateway-client", SubjectID: "parent", Resource: edge.TargetResource, ReceivingThumbprint: "gateway-key", Scopes: []string{"read"}}
	subject := &exchangeSubject{value: delegation.Subject{Claims: parent, Active: true}}
	denied, err := delegation.New(exchangePolicy{deny: true}, subject, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.PlanExchange(context.Background(), cmd); err == nil || subject.reads != 0 {
		t.Fatal("denial loaded protected subject")
	}
	service, err := delegation.New(exchangePolicy{edge: edge}, subject, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.PlanExchange(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ParentID != parent.ID || plan.GrantID != parent.GrantID || plan.Revision != 7 || plan.Subject != parent.Subject || plan.ExpiresAt.After(parent.ExpiresAt) || plan.ReceivingThumbprint != "gateway-key" {
		t.Fatal("lost ancestry or authority ceiling")
	}
	for name, mutate := range map[string]func(){"expansion": func() { cmd.Scopes = []string{"write"} }, "foreign tenant": func() { cmd.Scope.TenantID = "b" }, "second hop": func() { subject.value.Actors = []string{"prior-gateway"} }, "revoked": func() { subject.value.Active = false }, "wrong recipient": func() { cmd.CallerClientID = "attacker" }} {
		t.Run(name, func(t *testing.T) {
			original := cmd
			old := subject.value
			mutate()
			if _, err := service.PlanExchange(context.Background(), cmd); err == nil {
				t.Fatal("unsupported exchange accepted")
			}
			cmd = original
			subject.value = old
		})
	}
}

// Fosite's handler registry can invoke a service-owned custom grant without a
// SQL handle. This probe makes no credential and is never composed in production.
type exchangeHook struct {
	called bool
	plan   func(context.Context) error
}

func (h *exchangeHook) CanHandleTokenEndpointRequest(_ context.Context, r fosite.AccessRequester) bool {
	return r.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange")
}
func (*exchangeHook) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool { return false }
func (h *exchangeHook) HandleTokenEndpointRequest(ctx context.Context, r fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, r) {
		return fosite.ErrUnknownRequest
	}
	h.called = true
	if h.plan != nil {
		return h.plan(ctx)
	}
	return nil
}
func (*exchangeHook) PopulateTokenEndpointResponse(context.Context, fosite.AccessRequester, fosite.AccessResponder) error {
	return fosite.ErrUnsupportedGrantType
}

var _ fosite.TokenEndpointHandler = (*exchangeHook)(nil)

func TestFositeCustomExchangeRegistration(t *testing.T) {
	now := time.Now()
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	subject := &exchangeSubject{value: delegation.Subject{Active: true, Claims: domain.AccessClaims{ID: "parent", Scope: scope, GrantID: "root", Revision: 1, Subject: "user:alice", PrincipalType: "user", Resource: "https://gateway.example", Scopes: []string{"read"}, ExpiresAt: now.Add(time.Minute)}}}
	service, err := delegation.New(exchangePolicy{edge: delegation.Edge{Scope: scope, RecipientClientID: "gateway", SourceResource: "https://gateway.example", TargetResource: "https://downstream.example", Scopes: []string{"read"}, Lifetime: time.Minute}}, subject, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	h := &exchangeHook{plan: func(ctx context.Context) error {
		plan, err := service.PlanExchange(ctx, delegation.Command{Scope: scope, CallerClientID: "gateway", SubjectID: "parent", Resource: "https://downstream.example", ReceivingThumbprint: "verified-gateway-key", Scopes: []string{"read"}})
		if err == nil && plan.ParentID != "parent" {
			t.Fatal("service hook lost lineage")
		}
		return err
	}}
	config := &fosite.Config{}
	config.TokenEndpointHandlers.Append(h)
	request := fosite.NewAccessRequest(&grantSession{})
	request.GrantTypes = fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
	for _, handler := range config.GetTokenEndpointHandlers(context.Background()) {
		if handler.CanHandleTokenEndpointRequest(context.Background(), request) {
			if err := handler.HandleTokenEndpointRequest(context.Background(), request); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !h.called {
		t.Fatal("custom exchange hook not reached")
	}
}
