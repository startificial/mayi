package authentication

import (
	"context"
	"github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
)

type Sessions struct {
	store SessionControlStore
	clock Clock
	scope grants.Scope
}

func NewSessions(store SessionControlStore, clock Clock, scope grants.Scope) (*Sessions, error) {
	if store == nil || clock == nil || !scope.Valid() {
		return nil, ErrUnavailable
	}
	return &Sessions{store, clock, scope}, nil
}
func (s *Sessions) valid(p SessionProof) bool {
	return p.Scope == s.scope && authorization.ValidHandleHash(p.SessionHash) && authorization.ValidHandleHash(p.BrowserHash)
}
func (s *Sessions) List(ctx context.Context, p SessionProof) ([]SessionInfo, error) {
	if !s.valid(p) {
		return nil, ErrDenied
	}
	return s.store.ListSessions(ctx, p, s.clock.Now())
}
func (s *Sessions) Revoke(ctx context.Context, p SessionProof, id string) error {
	if !s.valid(p) || !authorization.ValidHandleHash(id) {
		return ErrDenied
	}
	return s.store.RevokeSession(ctx, p, id, s.clock.Now())
}

func (s *Sessions) Touch(ctx context.Context, p SessionProof) error {
	if !s.valid(p) {
		return ErrDenied
	}
	return s.store.TouchSession(ctx, p, s.clock.Now())
}
