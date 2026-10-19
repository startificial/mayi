package tokens

import (
	"context"
	"github.com/startificial/mayi/internal/domain/resources"
	"slices"
)

type StatusService struct {
	store    StatusStore
	hasher   SecretHasher
	material MaterialSource
}

func NewStatus(store StatusStore, h SecretHasher, m MaterialSource) (*StatusService, error) {
	if store == nil || h == nil || m == nil {
		return nil, ErrUnavailable
	}
	return &StatusService{store, h, m}, nil
}

// Introspect authenticates and authorizes the resource reference before the
// credential lookup. Zero Claims is the standard inactive result, not an error.
func (s *StatusService) Introspect(ctx context.Context, caller StatusCaller, raw, resource string) (Result, error) {
	if !caller.Scope.Valid() || caller.ClientID == "" || !caller.Introspection || !resources.ValidURI(resource) || !slices.Contains(caller.Resources, resource) {
		return Result{}, ErrInvalidCredential
	}
	if raw == "" || len(raw) > 65536 {
		return Result{}, nil
	}
	hash, err := s.hasher.Digest(caller.Scope, "access_token", raw)
	if err != nil {
		hash = s.material.DigestAccessToken(raw)
	}
	return s.store.AccessStatus(ctx, caller, hash, resource)
}
func (s *StatusService) Revoke(ctx context.Context, caller StatusCaller, raw, hint string) error {
	if !caller.Scope.Valid() || caller.ClientID == "" {
		return ErrInvalidCredential
	}
	if raw == "" || len(raw) > 65536 {
		return nil
	}
	// Both searches are owner-scoped and deliberately reveal no credential state.
	{ // A hint is advisory; a wrong hint cannot prevent revocation.
		if hash, err := s.hasher.Digest(caller.Scope, RefreshToken, raw); err == nil {
			if err := s.store.RevokeCredential(ctx, caller, hash, RefreshToken); err != nil {
				return err
			}
		}
	}
	hash, err := s.hasher.Digest(caller.Scope, "access_token", raw)
	if err != nil {
		hash = s.material.DigestAccessToken(raw)
	}
	return s.store.RevokeCredential(ctx, caller, hash, "access_token")
}
