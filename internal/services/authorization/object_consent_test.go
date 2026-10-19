package authorization_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/services/authorization"
)

type objectAuthority struct {
	t                                                       *testing.T
	s                                                       *store
	projection                                              domain.ObjectConsentProjection
	calls, displayLoads                                     int
	held, deny, unavailable, noCallback, twice, ignoreError bool
	before                                                  func()
}

func (a *objectAuthority) WithObjectConsent(ctx context.Context, q authorization.ObjectConsentQuery, fn func(domain.ObjectConsentProjection) error) error {
	a.t.Helper()
	a.calls++
	if a.s.inTransaction {
		a.t.Fatal("resource guard acquired while Mayi transaction held")
	}
	if ctx.Err() != nil || a.unavailable {
		return authorization.ErrUnavailable
	}
	if a.deny {
		return authorization.ErrDenied
	}
	if q.Subject != a.s.principal.Subject || q.TenantIssuer != a.s.principal.TenantIssuer || q.AuthorizationHash != a.s.workflow.Snapshot().HandleHash || q.ClientID != a.s.workflow.Snapshot().Request.ClientID || !q.Ceiling.Equal(a.s.workflow.Snapshot().Request.ObjectCeiling) {
		a.t.Fatal("resource query lost trusted exact correlation")
	}
	a.held = true
	defer func() { a.held = false }()
	if a.before != nil {
		a.before()
	}
	if a.noCallback {
		return nil
	}
	a.displayLoads++
	err := fn(a.projection)
	if a.twice {
		err = fn(a.projection)
	}
	if a.ignoreError {
		return nil
	}
	return err
}

func objectConsentSetup(t *testing.T) (*authorization.Service, *store, *clock, *material, authorization.AccessProof, *objectAuthority) {
	t.Helper()
	svc, s, c, m, _, pushedProof := pushedSetup(t)
	begun, err := svc.BeginPushed(context.Background(), pushedProof)
	if err != nil {
		t.Fatal(err)
	}
	p := authorization.AccessProof{TenantIssuer: s.principal.TenantIssuer, SessionHash: s.principal.SessionHash, AuthorizationHash: s.workflow.Snapshot().HandleHash, BrowserBindingHash: pushedProof.BrowserBindingHash, CSRFHash: s.workflow.Snapshot().CSRFHash}
	if begun.Handle == "" {
		t.Fatal("no workflow")
	}
	w := s.workflow.Snapshot()
	d := w.Request.ObjectCeiling.Snapshot().Details[0]
	projection, err := domain.NewObjectConsentProjection(domain.ObjectConsentSpec{AuthorizationHash: w.HandleHash, ClientID: w.Request.ClientID, Subject: s.principal.Subject, Ceiling: w.Request.ObjectCeiling, PermissionVersion: 7, Objects: []domain.ConsentObject{{Type: d.Type, Identifier: d.Identifier, Name: "Resource-owned object"}}})
	if err != nil {
		t.Fatal(err)
	}
	a := &objectAuthority{t: t, s: s, projection: projection}
	s.objectGuard = a
	svc, err = authorization.New(s, c, m, a)
	if err != nil {
		t.Fatal(err)
	}
	return svc, s, c, m, p, a
}

func TestObjectConsentDisplaysOnlyAuthorizedExactRequestedActions(t *testing.T) {
	svc, s, _, m, p, a := objectConsentSetup(t)
	before := m.next
	view, err := svc.PrepareConsent(context.Background(), p)
	if err != nil || view.DecisionAvailable || view.PermissionVersion != 7 || len(view.Objects) != 1 || view.Objects[0].Name != "Resource-owned object" || view.Objects[0].Identifier != "workflow:123" || len(view.Objects[0].Actions) != 1 || view.Objects[0].Actions[0].Name != "read" || view.Objects[0].Actions[0].Description != "Read object" {
		t.Fatal("invalid object display", view, err)
	}
	if a.held || a.calls != 1 || a.displayLoads != 1 || s.workflow.Snapshot().ConsentSessionHash != p.SessionHash || m.next != before {
		t.Fatal("guard, session binding or entropy order")
	}
	view.Objects[0].Actions[0].Name = "write"
	again, err := svc.PrepareConsent(context.Background(), p)
	if err != nil || again.Objects[0].Actions[0].Name != "read" {
		t.Fatal("caller mutated view", err)
	}
	if result, err := svc.Decide(context.Background(), authorization.Decision{Proof: p, Approve: true}); !errors.Is(err, authorization.ErrDenied) || result.Code != "" || m.next != before || s.completions != 0 {
		t.Fatal("display enabled approval before durable evidence", err)
	}
}

func TestObjectConsentDeniesBeforeResourceDisplay(t *testing.T) {
	for _, mode := range []string{"anonymous", "foreign tenant", "session revoked", "no PAR", "resource deny", "resource outage"} {
		t.Run(mode, func(t *testing.T) {
			svc, s, _, m, p, a := objectConsentSetup(t)
			before := m.next
			switch mode {
			case "anonymous":
				p.SessionHash = ""
			case "foreign tenant":
				p.TenantIssuer.TenantID = "b"
			case "session revoked":
				s.recheckDenied = true
			case "no PAR":
				w := s.workflow.Snapshot()
				w.PushedRequestHash = ""
				var err error
				s.workflow, err = domain.New(w)
				if err != nil {
					t.Fatal(err)
				}
			case "resource deny":
				a.deny = true
			case "resource outage":
				a.unavailable = true
			}
			view, err := svc.PrepareConsent(context.Background(), p)
			if err == nil || view.ClientID != "" || len(view.Objects) != 0 || a.displayLoads != 0 || a.held || s.workflow.Snapshot().ConsentSessionHash != "" || m.next != before {
				t.Fatal("denial disclosed or bound object request", err)
			}
			if mode != "resource deny" && mode != "resource outage" && a.calls != 0 {
				t.Fatal("unauthorized resource call")
			}
		})
	}
}

func TestObjectConsentRechecksAfterGuardAcquisitionAndNeverReturnsUncommittedDisplay(t *testing.T) {
	for _, mode := range []string{"session revoked", "policy changed", "redirect changed", "workflow expired", "commit failed", "no callback", "duplicate callback", "swallowed error", "substituted subject", "substituted workflow", "substituted client", "zero projection"} {
		t.Run(mode, func(t *testing.T) {
			svc, s, c, m, p, a := objectConsentSetup(t)
			before := m.next
			a.before = func() {
				switch mode {
				case "session revoked", "swallowed error":
					s.recheckDenied = true
				case "policy changed":
					s.registration.Policy.Version++
				case "redirect changed":
					s.registration.Client.RedirectURIs = []string{"https://other.example/cb"}
				case "workflow expired":
					c.now = c.now.Add(5 * time.Minute)
				case "commit failed":
					s.commitFailure = true
				}
			}
			a.noCallback = mode == "no callback"
			a.twice = mode == "duplicate callback"
			a.ignoreError = mode == "swallowed error"
			if strings.HasPrefix(mode, "substituted") {
				v := a.projection.Snapshot()
				switch mode {
				case "substituted subject":
					v.Subject = "user:bob"
				case "substituted workflow":
					v.AuthorizationHash = strings.Repeat("e", 64)
				case "substituted client":
					v.ClientID = "other"
				}
				var err error
				a.projection, err = domain.NewObjectConsentProjection(v)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "zero projection" {
				a.projection = domain.ObjectConsentProjection{}
			}
			view, err := svc.PrepareConsent(context.Background(), p)
			if err == nil || view.ClientID != "" || len(view.Objects) != 0 || a.held || m.next != before || s.completions != 0 {
				t.Fatal("invalid guard outcome returned authority/display", err)
			}
			if mode != "duplicate callback" && s.workflow.Snapshot().ConsentSessionHash != "" {
				t.Fatal("failed operation bound session")
			}
		})
	}
}
