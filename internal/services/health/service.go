// Package health evaluates readiness through bounded infrastructure ports.
package health

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	"slices"
)

var ErrUnavailable = errors.New("dependencies unavailable")

type TenantSigner struct {
	Scope  grants.Scope
	Signer Signer
}
type Service struct {
	database Database
	keys     KeyState
	signers  []TenantSigner
}

func New(database Database, keys KeyState, signers []TenantSigner) (*Service, error) {
	if database == nil || keys == nil || len(signers) == 0 || len(signers) > 32 {
		return nil, ErrUnavailable
	}
	seen := map[grants.Scope]bool{}
	for _, s := range signers {
		if !s.Scope.Valid() || s.Signer == nil || seen[s.Scope] {
			return nil, ErrUnavailable
		}
		seen[s.Scope] = true
	}
	return &Service{database: database, keys: keys, signers: slices.Clone(signers)}, nil
}
func (s *Service) Ready(ctx context.Context) error {
	if err := s.database.CheckHealth(ctx); err != nil {
		return ErrUnavailable
	}
	for _, signer := range s.signers {
		version, err := s.keys.ActiveSigningKey(ctx, signer.Scope)
		if err != nil || version < 1 {
			return ErrUnavailable
		}
		if err := signer.Signer.Check(ctx, signer.Scope, version); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}
