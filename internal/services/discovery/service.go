// Package discovery serves only public, tenant-scoped issuer/key projections.
package discovery

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
)

var ErrUnavailable = errors.New("discovery unavailable")

type Service struct{ directory Directory }
type Document struct {
	Scope grants.Scope
	Keys  []identity.PublicKey
}

func New(directory Directory) (*Service, error) {
	if directory == nil {
		return nil, ErrUnavailable
	}
	return &Service{directory: directory}, nil
}
func (s *Service) Document(ctx context.Context, scope grants.Scope) (Document, error) {
	if !scope.Valid() {
		return Document{}, ErrUnavailable
	}
	keys, err := s.directory.PublishedKeys(ctx, scope)
	if err != nil || len(keys) == 0 {
		return Document{}, ErrUnavailable
	}
	return Document{Scope: scope, Keys: keys}, nil
}
