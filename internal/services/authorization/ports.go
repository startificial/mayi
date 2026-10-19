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

// ObjectConsentQuery contains only authenticated actor/workflow correlation and
// requested object references. It contains no state, redirect, CSRF or payload.
type ObjectConsentQuery struct {
	TenantIssuer      grants.Scope
	Subject           string
	AuthorizationHash string
	ClientID          string
	Ceiling           grants.ObjectCeiling
}

// ObjectConsentAuthority is the resource owner's authoritative integration.
// Authorize every requested tuple for the principal before reading display
// metadata. Deny missing/foreign/forbidden objects generically, as ErrDenied;
// availability failures are ErrUnavailable. Return only exact requested tuples.
//
// Acquire a current permission/display guard before invoking fn, hold it until
// fn returns (including the Mayi transaction's commit), and release on every
// exit. Invoke fn exactly once, synchronously; never retry it or call it after
// returning. All relevant resource permission/display changes must conflict
// with this guard. A cached allow or unguarded remote boolean is insufficient.
// No Mayi transaction or pool connection is held while acquiring this guard.
type ObjectConsentAuthority interface {
	WithObjectConsent(context.Context, ObjectConsentQuery, func(domain.ObjectConsentProjection) error) error
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
	// Record the first exact presentation atomically with session binding/audit.
	// Repeated identical presentation is idempotent; replacement is denied.
	RecordObjectPresentation(context.Context, domain.Transaction, domain.ObjectConsentProjection, time.Time) error
	// Authenticate the stored presentation against this transaction's consent
	// proof and fresh resource decision before entropy. Return its exact snapshot
	// and pin a transaction-local approval authorization for CompleteAuthorization.
	AuthorizeObjectApproval(context.Context, domain.Transaction, domain.ObjectConsentProjection, time.Time) (domain.ObjectConsentProjection, error)
	// RecheckConsent validates session/membership and the reference before payload
	// load, under RunAuthorization's coordination lock. All identity invalidation
	// must use the conflicting tenant write lock; direct DBA writes are trusted.
	RecheckConsent(context.Context, AccessProof, Principal, time.Time) error
	// CompleteAuthorization atomically consumes the pending workflow, inserts the
	// exact revision and <=60s code if approved, and records audit/outbox evidence.
	CompleteAuthorization(context.Context, domain.Transaction, grants.Revision, time.Time) error
}
