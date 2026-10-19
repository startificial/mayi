package tokens

import (
	"context"
	"time"

	"github.com/startificial/mayi/internal/domain/grants"
	domaintokens "github.com/startificial/mayi/internal/domain/tokens"
)

// Authorizer checks the authenticated client and tenant before any protected load.
// Its version must be rechecked under the transaction's policy lock until commit.
type Authorizer interface {
	AuthorizeRedemption(context.Context, Caller, string) (uint64, error)
}

// SecretHasher implements the pinned purpose/tenant/version-separated keyed
// digest policy. Raw credentials never enter a persistence port.
type SecretHasher interface {
	Digest(grants.Scope, string, string) (string, error)
}
type Clock interface{ Now() time.Time }
type PKCEVerifier interface {
	VerifyS256(challenge, verifier string) error
}

// Signer produces an RFC 9068 token via a reviewed protocol/JOSE adapter and a
// non-exportable KMS/HSM key. A signature is not a committed issuance.
type Signer interface {
	SignAccessToken(context.Context, domaintokens.AccessClaims) (string, error)
}

type IdentitySigner interface {
	SignIdentityToken(context.Context, domaintokens.IdentityClaims) (string, error)
}

// MaterialSource generates fresh unpredictable values. Only the hash of a refresh
// secret crosses the persistence boundary. Plaintext is returned after commit.
type MaterialSource interface {
	NewMaterial(context.Context) (Material, error)
	DigestAccessToken(string) string
}

// UnitOfWork invokes the callback once, synchronously. It serializes credential,
// grant/family and policy state, and commits consume+issuance+audit atomically.
// Callback/commit errors roll back all writes. A nil result means durable commit.
// It must not retry callbacks: signing and entropy are external effects.
type UnitOfWork interface {
	Run(context.Context, grants.Scope, func(Transaction) error) error
}

type Transaction interface {
	// Credential is a tenant-scoped authentication projection, not a grant payload.
	Credential(context.Context, string) (Credential, error)
	// Called only after client/binding/S256 possession checks. The narrow
	// credential lookup deliberately contains no protected object identifiers.
	CredentialObjects(context.Context, Credential) (grants.ObjectCeiling, error)
	GrantRevision(context.Context, string, uint64) (GrantState, error)
	// RevokeReplay revokes code descendants or the entire refresh grant/family,
	// including derived/exchanged credentials, and records the replay audit event.
	RevokeReplay(context.Context, Credential) error
	// CommitIssuance checks uniqueness, consumes the credential, and writes a
	// successor (refresh only), lineage, and audit in the current transaction.
	CommitIssuance(context.Context, Credential, Issuance) error
}
