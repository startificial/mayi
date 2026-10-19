package delivery

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
)

type Security struct{ store SecurityStore }

func NewSecurity(store SecurityStore) (*Security, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &Security{store}, nil
}
func (s *Security) Denied(ctx context.Context, scope grants.Scope, operation string, status int) error {
	if !scope.Valid() || status < 400 || status > 599 {
		return ErrUnavailable
	}
	switch operation {
	case "authorization", "token", "introspection", "administration", "session", "request":
	default:
		return ErrUnavailable
	}
	return s.store.RecordDenied(ctx, scope, operation, status)
}
