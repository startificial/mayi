package authentication

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	"time"
)

type Clock interface{ Now() time.Time }
type Secrets interface {
	NewSecret(context.Context) (string, error)
	Digest(string) string
}
type Provider interface {
	ID() string
	Fingerprint() string
	AuthorizationURL(state, nonce, verifier string) (string, error)
	Authenticate(context.Context, string, string, string, time.Time) (identity.Assertion, error)
}

// Store owns atomic login claim and session transitions. Operations take the
// tenant coordination row FOR UPDATE before identity rows. No external I/O is
// performed while holding these locks. Membership/mapping are never auto-created.
type Store interface {
	LoginClient(context.Context, grants.Scope, string, string, time.Time) (string, error)
	StartLogin(context.Context, identity.Login) error
	ClaimLogin(context.Context, identity.Login, time.Time) error
	CompleteLogin(context.Context, identity.Login, identity.Assertion, string, string, time.Time) error
	EndSession(context.Context, grants.Scope, string, string, time.Time) error
}

// UpstreamTransport is the constrained wire boundary used by the provider
// adapter. It never follows redirects or accepts token-supplied key locations.
type UpstreamTransport interface {
	GetJSON(context.Context, string) ([]byte, error)
	PostForm(context.Context, string, []FormField, string, string) ([]byte, error)
}
type FormField struct{ Name, Value string }
