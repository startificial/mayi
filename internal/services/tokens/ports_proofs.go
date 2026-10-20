package tokens

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type ProofVerifier interface {
	VerifyProof(context.Context, ProofRequest, time.Time) (VerifiedProof, error)
}
type ProofReplayStore interface {
	// Recheck nonce validity and consume jti atomically before accepting a proof.
	ConsumeProof(context.Context, grants.Scope, ProofReplay) error
}
type ProofReplay struct {
	Thumbprint, ID, NonceHash, Purpose, Target string
	ExpiresAt                                  time.Time
}

// Nonces are scoped to the tenant, proof purpose, public target and key. They
// may be reused with fresh jti values until expiry; replay remains authoritative.
type ProofNonceStore interface {
	ValidProofNonce(context.Context, grants.Scope, string, string, string, string) (bool, error)
	RememberProofNonce(context.Context, grants.Scope, string, string, string, string, time.Time) error
}
type ProofNonceSource interface {
	NewNonce(context.Context, grants.Scope) (string, string, error)
	HashNonce(grants.Scope, string) (string, error)
}
