// Package services contains the reference application's use cases and effect ports.
// It has no dependency on Mayi's privileged internal packages.
package services

import (
	"context"
	"time"
)

// CredentialContext is supplied from trusted application configuration and the
// authenticated session record. It must never be reconstructed from an envelope.
// Generation is the store's expected monotonic revision, not an attacker-supplied
// value read alongside the ciphertext.
type CredentialContext struct {
	Tenant, Issuer, Client, Resource, Session, Purpose string
	Generation                                         uint64
}

// Envelope contains no plaintext credentials. Version and KeyID are authenticated
// along with CredentialContext, although neither is confidential.
type Envelope struct {
	Version    uint32
	KeyID      string
	Ciphertext []byte
}

type Tokens struct {
	Access, Refresh, Identity, Type string
	ExpiresAt                       time.Time
}
type CredentialCipher interface {
	SealTokens(context.Context, CredentialContext, Tokens) (Envelope, error)
	OpenTokens(context.Context, CredentialContext, Envelope) (Tokens, error)
	SealLogin(context.Context, CredentialContext, LoginMaterial) (Envelope, error)
	OpenLogin(context.Context, CredentialContext, Envelope) (LoginMaterial, error)
}

type Clock interface{ Now() time.Time }
type Session struct {
	ID          string
	Generation  uint64
	Credentials Envelope
	ExpiresAt   time.Time
}

// WithSession authenticates the opaque cookie and serializes all use of the
// session until the callback returns. It must not retry the callback.
type SessionStore interface {
	Create(context.Context, Session) (string, error)
	WithSession(context.Context, string, func(SessionLease) error) error
}
type SessionLease interface {
	Session() Session
	// BeginRefresh durably marks the old refresh token unavailable before its
	// uncertain network outcome. A failed refresh leaves the session invalid.
	BeginRefresh(context.Context) error
	Replace(context.Context, uint64, Envelope) error
	Invalidate(context.Context) error
}
type OAuthClient interface {
	Refresh(context.Context, string) (Tokens, error)
}
type API interface {
	ReadObject(context.Context, string, string) ([]byte, error)
}

type LoginMaterial struct {
	ID, State, Nonce, Verifier string
	CreatedAt                  time.Time
}
type LoginSource interface {
	NewLogin(context.Context) (LoginMaterial, error)
}
type LoginClient interface {
	Begin(context.Context, AuthorizationRequest) (string, error)
	ExchangeIdentity(context.Context, string, LoginMaterial) (Tokens, error)
}
type AuthorizationRequest struct {
	State, Nonce, Verifier, Type, Identifier, Permission string
	Actions                                              []string
}
