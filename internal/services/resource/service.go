// Package resource is the shared, transport-independent resource enforcement.
package resource

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"slices"
	"time"
)

var ErrDenied = errors.New("resource access denied")
var ErrUnavailable = errors.New("resource authority unavailable")
var ErrInsufficientScope = errors.New("resource permission scope required")
var ErrInvalidProof = errors.New("invalid resource proof")

type NonceChallenge struct{ Nonce string }

func (*NonceChallenge) Error() string { return "resource DPoP nonce required" }
func (*NonceChallenge) Unwrap() error { return ErrDenied }

type Request struct{ Type, Identifier, Action, Permission, Proof, Method, URL string }
type Decision struct {
	Claims  domain.AccessClaims
	Request Request
}
type Service struct {
	status      Status
	permissions PermissionGuard
	clock       Clock
	scope       grants.Scope
	resource    string
	profiles    []resources.ObjectProfile
	requireDPoP bool
}

func New(status Status, permissions PermissionGuard, clock Clock, scope grants.Scope, resource string, profiles []resources.ObjectProfile, requireDPoP bool) (*Service, error) {
	if status == nil || permissions == nil || clock == nil || !scope.Valid() || !resources.ValidURI(resource) || len(profiles) == 0 {
		return nil, ErrUnavailable
	}
	for _, p := range profiles {
		if p.Snapshot().Scope != scope || p.Snapshot().Resource != resource {
			return nil, ErrUnavailable
		}
	}
	return &Service{status, permissions, clock, scope, resource, slices.Clone(profiles), requireDPoP}, nil
}
func (s *Service) WithAccess(ctx context.Context, raw string, r Request, fn func(context.Context, Decision) error) error {
	if fn == nil || raw == "" || len(raw) > 65536 || !grants.ValidScopes([]string{r.Permission}) {
		return ErrDenied
	}
	if _, err := resources.ValidateObjectRequest(s.scope, s.resource, s.profiles, []grants.ObjectDetail{{Type: r.Type, Identifier: r.Identifier, Actions: []string{r.Action}}}); err != nil {
		return ErrDenied
	}
	verified, err := s.status.ValidateToken(ctx, TokenRequest{Token: raw, Resource: s.resource, Proof: r.Proof, Method: r.Method, URL: r.URL})
	if err != nil {
		if ctx.Err() != nil {
			return errors.Join(ErrUnavailable, ctx.Err())
		}
		var nonce *NonceChallenge
		if errors.As(err, &nonce) {
			return nonce
		}
		if errors.Is(err, ErrInvalidProof) {
			return errors.Join(ErrDenied, ErrInvalidProof)
		}
		if errors.Is(err, ErrDenied) {
			return ErrDenied
		}
		return ErrUnavailable
	}
	c := verified.Claims
	if s.requireDPoP && c.BindingThumbprint == "" {
		return ErrDenied
	}
	now := s.clock.Now()
	if c.Scope != s.scope || c.Resource != s.resource || c.ID == "" || !now.Before(c.ExpiresAt) || c.IssuedAt.After(now.Add(5*time.Second)) || c.ExpiresAt.After(c.IssuedAt.Add(15*time.Minute)) || !c.ObjectCeiling.Permits(s.scope, s.resource, r.Type, r.Identifier, r.Action) {
		return ErrDenied
	}
	if c.BindingThumbprint != "" && !verified.ProofVerified {
		return errors.Join(ErrDenied, ErrInvalidProof)
	}
	if _, err := resources.ValidateObjectRequest(s.scope, s.resource, s.profiles, c.ObjectCeiling.Snapshot().Details); err != nil {
		return ErrDenied
	}
	if _, err := grants.NewRevision(grants.RevisionSpec{Scope: c.Scope, GrantID: c.GrantID, Number: c.Revision, ClientID: c.ClientID, Subject: c.Subject, PrincipalType: c.PrincipalType, Resource: c.Resource, Scopes: c.Scopes, ObjectCeiling: c.ObjectCeiling, ExpiresAt: c.ExpiresAt}); err != nil {
		return ErrDenied
	}
	if !slices.Contains(c.Scopes, r.Permission) {
		return errors.Join(ErrDenied, ErrInsufficientScope)
	}
	decision := Decision{Claims: c, Request: r}
	calls := 0
	var callbackErr error
	err = s.permissions.WithPermission(ctx, decision, func(ctx context.Context) error {
		calls++
		if calls != 1 {
			return ErrUnavailable
		}
		if !s.clock.Now().Before(c.ExpiresAt) {
			return ErrDenied
		}
		callbackErr = fn(ctx, decision)
		return callbackErr
	})
	if err != nil {
		return err
	}
	if callbackErr != nil {
		return callbackErr
	}
	if calls != 1 {
		return ErrUnavailable
	}
	return nil
}
