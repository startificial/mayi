package clients

import (
	"context"
	domain "github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type Clock interface{ Now() time.Time }
type Store interface {
	Authentication(context.Context, grants.Scope, string) (Authentication, error)
	ConsumeAssertion(context.Context, grants.Scope, string, string, time.Time) error
	RotateSecret(context.Context, grants.Scope, string, string, time.Time, time.Time, string) error
	ConfigureKeys(context.Context, grants.Scope, string, string, string, string) error
}
type AssertionVerifier interface {
	ValidateKeys(context.Context, string, string) error
	VerifyClientAssertion(context.Context, string, string, string, string, string, time.Time) (Assertion, error)
}
type Secrets interface {
	NewClientSecret(context.Context) (string, string, error)
	DigestClientSecret(string) (string, error)
	Matches(string, string) bool
}
type Authentication struct {
	Resources     []string
	Client        domain.Client
	Version       uint64
	JWKS, JWKSURI string
	SecretHashes  []SecretHash
	Scopes        []string
}
type SecretHash struct {
	Hash      string
	ExpiresAt time.Time
}
type Assertion struct {
	ID        string
	ExpiresAt time.Time
}

type KeyTransport interface {
	FetchKeys(context.Context, string) ([]byte, error)
}
