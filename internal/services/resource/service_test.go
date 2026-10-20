package resource

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/domain/tokens"
)

type statusFixture struct {
	claims tokens.AccessClaims
	err    error
}

func (f statusFixture) ValidateToken(context.Context, TokenRequest) (ValidatedToken, error) {
	return ValidatedToken{Claims: f.claims}, f.err
}

type forbiddenGuard struct{ t *testing.T }

func (g forbiddenGuard) WithPermission(context.Context, Decision, func(context.Context) error) error {
	g.t.Fatal("denied request loaded current permissions or payload")
	return ErrUnavailable
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestResourceScopeChallengeRequiresValidLocalAuthorityBeforePermissionLoad(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	profile, err := resources.NewObjectProfile(resources.ObjectProfileSpec{Scope: scope, Resource: "https://api.example", Type: "https://api.example/types/document/v1", Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read"}}})
	if err != nil {
		t.Fatal(err)
	}
	ceiling, err := profile.ValidateRequest(scope, "https://api.example", []grants.ObjectDetail{{Type: profile.Snapshot().Type, Identifier: "123", Actions: []string{"read"}}})
	if err != nil {
		t.Fatal(err)
	}
	base := tokens.AccessClaims{Scope: scope, ID: "token-1", GrantID: "grant-1", Revision: 1, ClientID: "web", Subject: "user:alice", PrincipalType: "user", Resource: "https://api.example", Scopes: []string{"other"}, ObjectCeiling: ceiling, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	for _, mode := range []string{"scope", "foreign tenant", "foreign resource", "invalid principal", "foreign object", "unavailable", "required binding", "nonce", "invalid proof"} {
		t.Run(mode, func(t *testing.T) {
			claims := base
			var statusErr error
			switch mode {
			case "foreign tenant":
				claims.Scope.TenantID = "b"
			case "foreign resource":
				claims.Resource = "https://other.example"
			case "invalid principal":
				claims.Subject = ""
			case "unavailable":
				statusErr = ErrUnavailable
			case "nonce":
				statusErr = &NonceChallenge{Nonce: "v1." + strings.Repeat("A", 43)}
			case "invalid proof":
				statusErr = ErrInvalidProof
			}
			svc, err := New(statusFixture{claims, statusErr}, forbiddenGuard{t}, fixedClock{now}, scope, base.Resource, []resources.ObjectProfile{profile}, mode == "required binding")
			if err != nil {
				t.Fatal(err)
			}
			r := Request{Type: profile.Snapshot().Type, Identifier: "123", Action: "read", Permission: "read"}
			if mode == "foreign object" {
				r.Identifier = "124"
			}
			err = svc.WithAccess(context.Background(), "credential", r, func(context.Context, Decision) error { t.Fatal("payload loaded"); return nil })
			if mode == "scope" {
				if !errors.Is(err, ErrInsufficientScope) || !errors.Is(err, ErrDenied) {
					t.Fatal("scope failure lacks typed challenge", err)
				}
			} else if mode == "nonce" {
				var nonce *NonceChallenge
				if !errors.As(err, &nonce) {
					t.Fatal("nonce challenge lost", err)
				}
			} else if mode == "invalid proof" {
				if !errors.Is(err, ErrInvalidProof) {
					t.Fatal("proof error classification lost", err)
				}
			} else if mode == "unavailable" {
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal("dependency failure disguised as bad credential", err)
				}
			} else if !errors.Is(err, ErrDenied) || errors.Is(err, ErrInsufficientScope) {
				t.Fatal("foreign/invalid authority disclosed scope hint", err)
			}
		})
	}
}
