package resource

import (
	"context"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"time"
)

type Clock interface{ Now() time.Time }
type Status interface {
	ValidateToken(context.Context, TokenRequest) (ValidatedToken, error)
}
type ValidatedToken struct {
	Claims        domain.AccessClaims
	ProofVerified bool
}
type TokenRequest struct{ Token, Resource, Proof, Method, URL string }

// PermissionGuard is owned by the resource. It authorizes using narrow current
// ACL metadata, before payload load, and keeps policy stable through fn. The
// callback context may carry its adapter-private atomic transaction capability.
// No stale positive cache, asynchronous callback or callback retry is permitted.
type PermissionGuard interface {
	WithPermission(context.Context, Decision, func(context.Context) error) error
}
