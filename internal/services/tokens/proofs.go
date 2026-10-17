package tokens

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

// Method, URL and expected nonce come from trusted endpoint configuration.
// AccessToken is set only for a resource proof, requiring an ath claim.
type ProofRequest struct{ JWT, Method, URL, AccessToken, Nonce string }
type VerifiedProof struct {
	Thumbprint, ID string
	ExpiresAt      time.Time
}
type ProofService struct {
	verifier ProofVerifier
	replay   ProofReplayStore
	clock    Clock
}

func NewProofs(v ProofVerifier, r ProofReplayStore, c Clock) (*ProofService, error) {
	if v == nil || r == nil || c == nil {
		return nil, ErrUnavailable
	}
	return &ProofService{verifier: v, replay: r, clock: c}, nil
}
func (s *ProofService) Verify(ctx context.Context, scope grants.Scope, request ProofRequest) (string, error) {
	if !scope.Valid() || request.JWT == "" || len(request.JWT) > 8192 || request.Method == "" || request.URL == "" {
		return "", ErrInvalidCredential
	}
	proof, err := s.verifier.VerifyProof(ctx, request, s.clock.Now())
	if err != nil || proof.Thumbprint == "" || proof.ID == "" {
		return "", ErrInvalidCredential
	}
	if err := s.replay.ConsumeProof(ctx, scope, proof); err != nil {
		return "", ErrInvalidCredential
	}
	return proof.Thumbprint, nil
}
