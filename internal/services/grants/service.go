// Package grants owns user-facing durable-grant inspection and revocation.
package grants

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/authorization"
	domain "github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"slices"
)

var ErrDenied = errors.New("grant operation denied")
var ErrUnavailable = errors.New("grant authority unavailable")

type Service struct {
	store Store
	clock Clock
	scope domain.Scope
}

func New(store Store, clock Clock, scope domain.Scope) (*Service, error) {
	if store == nil || clock == nil || !scope.Valid() {
		return nil, ErrUnavailable
	}
	return &Service{store, clock, scope}, nil
}
func (s *Service) valid(p BrowserProof) bool {
	return p.Scope == s.scope && authorization.ValidHandleHash(p.SessionHash) && authorization.ValidHandleHash(p.BrowserHash)
}
func (s *Service) List(ctx context.Context, p BrowserProof) ([]Summary, error) {
	if !s.valid(p) {
		return nil, ErrDenied
	}
	var result []Summary
	err := s.store.WithUserGrants(ctx, p, s.clock.Now(), func(tx UserGrants) error { var err error; result, err = tx.List(ctx); return err })
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (s *Service) Revoke(ctx context.Context, p BrowserProof, id string) error {
	if !s.valid(p) || !resources.ValidID(id) {
		return ErrDenied
	}
	return s.store.WithUserGrants(ctx, p, s.clock.Now(), func(tx UserGrants) error {
		owned, err := tx.Owned(ctx, id)
		if err != nil {
			return err
		}
		if !owned {
			return nil
		}
		return tx.Revoke(ctx, id)
	})
}

// AdminRevoke supports an exact grant ID or the explicit user/client selectors.
// It never interprets an arbitrary request tenant as authority.
func (s *Service) AdminRevoke(ctx context.Context, a Operator, kind, id string) error {
	if a.Scope != s.scope || !resources.ValidID(a.ID) || !slices.Contains(a.Permissions, "grants:write") {
		return ErrDenied
	}
	if kind != "grant" && kind != "user" && kind != "client" || id == "" || len(id) > 256 {
		return ErrDenied
	}
	if kind == "user" && !domain.ValidUserSubject(id) {
		return ErrDenied
	}
	return s.store.RevokeAdministrator(ctx, s.scope, kind, id, a.ID)
}
