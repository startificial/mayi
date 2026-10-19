package authorization_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/authorization"
)

func (s *store) CreatePushed(_ context.Context, p domain.PushedRequest) error {
	if s.createFailure {
		return authorization.ErrUnavailable
	}
	s.pushed = p
	return nil
}
func (s *store) AuthorizePushed(_ context.Context, proof authorization.PushedProof, now time.Time) error {
	p := s.pushed.Snapshot()
	if !proof.Valid() || !s.pushed.ActiveAt(now) || proof.TenantIssuer != p.Request.TenantIssuer || proof.ClientID != p.Request.ClientID || proof.ReferenceHash != p.ReferenceHash || !s.registration.Client.Enabled || p.PolicyVersion != s.registration.Policy.Version {
		return authorization.ErrDenied
	}
	s.pushedAuthorized = true
	return nil
}
func (s *store) Pushed(context.Context, string) (domain.PushedRequest, error) {
	s.pushedLoads++
	if !s.pushedAuthorized {
		return domain.PushedRequest{}, authorization.ErrDenied
	}
	return s.pushed, nil
}
func (s *store) ConsumePushed(_ context.Context, p domain.PushedRequest, w domain.Transaction, _ time.Time) error {
	if s.createFailure {
		return authorization.ErrUnavailable
	}
	s.pushedConsumptions++
	s.pushed, s.workflow = p, w
	return nil
}

func pushedSetup(t *testing.T) (*authorization.Service, *store, *clock, *material, domain.Request, authorization.PushedProof) {
	t.Helper()
	svc, s, c, m, request, original := setup(t)
	request.State = "client-state-at-least-16"
	spec := resources.ObjectProfileSpec{Scope: request.TenantIssuer, Resource: request.ResourceURI, Type: s.registration.Client.AuthorizationDetailsTypes[0], Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read object"}}}
	profile, err := resources.NewObjectProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	s.registration.ObjectProfiles = []resources.ObjectProfile{profile}
	request.ObjectCeiling = objectRequest(t, spec)
	result, err := svc.Push(context.Background(), request)
	if err != nil || result.Reference == "" {
		t.Fatal(err)
	}
	return svc, s, c, m, request, authorization.PushedProof{TenantIssuer: request.TenantIssuer, ClientID: request.ClientID, ReferenceHash: s.pushed.Snapshot().ReferenceHash, BrowserBindingHash: original.BrowserBindingHash}
}

func objectRequest(t *testing.T, spec resources.ObjectProfileSpec) grants.ObjectCeiling {
	t.Helper()
	p, err := resources.NewObjectProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.ValidateRequest(spec.Scope, spec.Resource, []grants.ObjectDetail{{Type: spec.Type, Identifier: "workflow:123", Actions: []string{"read"}}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPushedDenialAuthenticatesReferenceBeforePayloadAndEntropy(t *testing.T) {
	for _, mode := range []string{"foreign tenant", "foreign issuer", "wrong client", "unknown reference", "expired", "policy changed", "disabled client"} {
		t.Run(mode, func(t *testing.T) {
			svc, s, c, m, _, proof := pushedSetup(t)
			switch mode {
			case "foreign tenant":
				proof.TenantIssuer.TenantID = "b"
			case "foreign issuer":
				proof.TenantIssuer.Issuer = "https://other.example/t/a"
			case "wrong client":
				proof.ClientID = "another"
			case "unknown reference":
				proof.ReferenceHash = strings.Repeat("f", 64)
			case "expired":
				c.now = c.now.Add(domain.PushedLifetime)
			case "policy changed":
				s.registration.Policy.Version++
			case "disabled client":
				s.registration.Client.Enabled = false
			}
			before := m.next
			out, err := svc.BeginPushed(context.Background(), proof)
			if !errors.Is(err, authorization.ErrDenied) || out.Handle != "" || out.CSRFToken != "" || s.pushedLoads != 0 || s.pushedConsumptions != 0 || m.next != before {
				t.Fatal("denial loaded payload, generated material or consumed reference", err)
			}
		})
	}
}

func TestPushedWorkflowKeepsSnapshotAndReturnsOnlyAfterCommit(t *testing.T) {
	for _, mode := range []string{"success", "storage failure", "commit failure", "entropy failure", "registration changed"} {
		t.Run(mode, func(t *testing.T) {
			svc, s, _, m, request, proof := pushedSetup(t)
			s.createFailure = mode == "storage failure"
			s.commitFailure = mode == "commit failure"
			m.fail = mode == "entropy failure"
			if mode == "registration changed" {
				s.registration.ObjectProfiles = nil
			}
			out, err := svc.BeginPushed(context.Background(), proof)
			if mode != "success" {
				if err == nil || out.Handle != "" || out.CSRFToken != "" || s.pushed.Snapshot().AuthorizationHash != "" {
					t.Fatal("failed start exposed or consumed authority", err)
				}
				return
			}
			w := s.workflow.Snapshot()
			if err != nil || out.Handle == "" || out.CSRFToken == "" || w.PushedRequestHash != proof.ReferenceHash || !w.Request.Equal(request) || s.pushed.Snapshot().AuthorizationHash != w.HandleHash {
				t.Fatal("pushed workflow lost correlation", err)
			}
			before, loads := m.next, s.pushedLoads
			if replay, err := svc.BeginPushed(context.Background(), proof); !errors.Is(err, authorization.ErrDenied) || replay.Handle != "" || m.next != before || s.pushedLoads != loads {
				t.Fatal("reference replay was reusable", err)
			}
		})
	}
}

func TestPushRejectsInvalidAuthorityBeforeMaterialAndReturnsNoUncommittedReference(t *testing.T) {
	for _, mode := range []string{"missing objects", "short state", "unallowed type", "storage", "commit", "entropy"} {
		t.Run(mode, func(t *testing.T) {
			svc, s, _, m, request, _ := pushedSetup(t)
			switch mode {
			case "missing objects":
				request.ObjectCeiling = grants.ObjectCeiling{}
			case "short state":
				request.State = "short"
			case "unallowed type":
				s.registration.Client.AuthorizationDetailsTypes = []string{"https://api.example/types/other/v1"}
			case "storage":
				s.createFailure = true
			case "commit":
				s.commitFailure = true
			case "entropy":
				m.fail = true
			}
			before := m.next
			out, err := svc.Push(context.Background(), request)
			if err == nil || out.Reference != "" || !out.ExpiresAt.IsZero() {
				t.Fatal("failed push exposed reference", err)
			}
			if (mode == "missing objects" || mode == "short state" || mode == "unallowed type") && m.next != before {
				t.Fatal("invalid request reached entropy")
			}
		})
	}
}
