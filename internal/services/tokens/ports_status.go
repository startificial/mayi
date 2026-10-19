package tokens

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
)

type StatusCaller struct {
	Scope                 grants.Scope
	ClientID              string
	AuthenticationVersion uint64
	Resources             []string
	Introspection         bool
}
type StatusStore interface {
	AccessStatus(context.Context, StatusCaller, string, string) (Result, error)
	RevokeCredential(context.Context, StatusCaller, string, string) error
}
