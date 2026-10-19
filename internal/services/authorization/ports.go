package authorization

import (
	"context"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type Clock interface{ Now() time.Time }
type MaterialSource interface {
	NewAuthorizationMaterial(context.Context) (Material, error)
}

// Store authenticates a narrow session/membership projection and authorizes the
// browser/CSRF reference before permitting a protected transaction load.
type Store interface {
	AuthorizeConsent(context.Context, AccessProof, time.Time) (Principal, error)
	// RunAuthorization holds the tenant coordination row FOR SHARE through callback
	// and commit. Policy, session and membership invalidation MUST hold that same
	// row FOR UPDATE before changing decision metadata.
	// Invoke once, synchronously; never retry entropy or effects in the callback.
	RunAuthorization(context.Context, grants.Scope, func(Transaction) error) error
}
type Transaction interface {
	CreatePushed(context.Context, domain.PushedRequest) error
	// Authenticate the narrow client/reference projection before payload load.
	AuthorizePushed(context.Context, PushedProof, time.Time) error
	Pushed(context.Context, string) (domain.PushedRequest, error)
	// Consume the reference and insert its exact workflow/audit/outbox atomically.
	ConsumePushed(context.Context, domain.PushedRequest, domain.Transaction, time.Time) error
	Registration(context.Context, string, string) (domain.Registration, error)
	CreateAuthorization(context.Context, domain.Transaction) error
	Authorization(context.Context, string) (domain.Transaction, error)
	BindConsentSession(context.Context, domain.Transaction) error
	// RecheckConsent validates session/membership and the reference before payload
	// load, under RunAuthorization's coordination lock. All identity invalidation
	// must use the conflicting tenant write lock; direct DBA writes are trusted.
	RecheckConsent(context.Context, AccessProof, Principal, time.Time) error
	// CompleteAuthorization atomically consumes the pending workflow, inserts the
	// exact revision and <=60s code if approved, and records audit/outbox evidence.
	CompleteAuthorization(context.Context, domain.Transaction, grants.Revision, time.Time) error
}
