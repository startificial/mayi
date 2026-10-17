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
	ConsumeProof(context.Context, grants.Scope, VerifiedProof) error
}
