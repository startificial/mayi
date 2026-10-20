package tokens

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"time"
)

// Method, URL and expected nonce come from trusted endpoint configuration.
// AccessToken is set only for a resource proof, requiring an ath claim.
type ProofRequest struct{ JWT, Method, URL, AccessToken, Nonce, ExpectedThumbprint string }
type VerifiedProof struct {
	Thumbprint, ID, Nonce string
	ExpiresAt             time.Time
}
type ProofService struct {
	verifier ProofVerifier
	replay   ProofReplayStore
	clock    Clock
	nonces   ProofNonceStore
	material ProofNonceSource
}

var ErrInvalidProof = errors.New("invalid DPoP proof")

type NonceChallenge struct{ Nonce string }

func (*NonceChallenge) Error() string { return "DPoP nonce required" }

func NewProofs(v ProofVerifier, r ProofReplayStore, n ProofNonceStore, m ProofNonceSource, c Clock) (*ProofService, error) {
	if v == nil || r == nil || n == nil || m == nil || c == nil {
		return nil, ErrUnavailable
	}
	return &ProofService{verifier: v, replay: r, clock: c, nonces: n, material: m}, nil
}
func (s *ProofService) Verify(ctx context.Context, scope grants.Scope, request ProofRequest) (string, error) {
	if !scope.Valid() || request.JWT == "" || len(request.JWT) > 8192 || request.Method == "" || len(request.Method) > 16 || request.URL == "" || len(request.URL) > 2048 || len(request.AccessToken) > 65536 || len(request.Nonce) > 128 || request.ExpectedThumbprint != "" && len(request.ExpectedThumbprint) != 43 {
		return "", ErrInvalidProof
	}
	target, ok := domain.ProofTarget(request.URL, false)
	if !ok {
		return "", ErrInvalidProof
	}
	proof, err := s.verifier.VerifyProof(ctx, request, s.clock.Now())
	if err != nil || proof.Thumbprint == "" || proof.ID == "" {
		return "", ErrInvalidProof
	}
	if request.ExpectedThumbprint != "" && proof.Thumbprint != request.ExpectedThumbprint {
		return "", ErrInvalidProof
	}
	purpose := "token"
	if request.AccessToken != "" {
		purpose = "resource"
	}
	hash, hashErr := s.material.HashNonce(scope, proof.Nonce)
	valid := false
	if hashErr == nil {
		valid, err = s.nonces.ValidProofNonce(ctx, scope, purpose, target, proof.Thumbprint, hash)
		if err != nil {
			return "", ErrUnavailable
		}
	}
	if !valid {
		raw, digest, err := s.material.NewNonce(ctx, scope)
		if err != nil || !domain.ValidProofNonce(raw) || len(digest) != 64 {
			return "", ErrUnavailable
		}
		if err := s.nonces.RememberProofNonce(ctx, scope, purpose, target, proof.Thumbprint, digest, s.clock.Now().Add(time.Minute)); err != nil {
			return "", ErrUnavailable
		}
		return "", &NonceChallenge{Nonce: raw}
	}
	if err := s.replay.ConsumeProof(ctx, scope, ProofReplay{Thumbprint: proof.Thumbprint, ID: proof.ID, ExpiresAt: proof.ExpiresAt, NonceHash: hash, Purpose: purpose, Target: target}); err != nil {
		if errors.Is(err, ErrInvalidCredential) {
			return "", ErrInvalidProof
		}
		return "", ErrUnavailable
	}
	return proof.Thumbprint, nil
}
