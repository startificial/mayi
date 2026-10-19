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
	RecordInactive(context.Context, StatusCaller, string) error
	RevokeCredential(context.Context, StatusCaller, string, string) error
}

// ResourceProofs verifies signature, target, ath and authoritative replay state.
type ResourceProofs interface {
	Verify(context.Context, grants.Scope, ProofRequest) (string, error)
}
