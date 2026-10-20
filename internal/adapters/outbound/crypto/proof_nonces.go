package crypto

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.ProofNonceSource = (*ProofNonces)(nil)

type ProofNonces struct {
	source *MaterialSource
	scope  grants.Scope
	hasher *SecretHasher
}

func NewProofNonces(scope grants.Scope, h *SecretHasher) (*ProofNonces, error) {
	source, err := NewKeyedMaterialSource(scope, h, "dpop_nonce")
	if err != nil {
		return nil, err
	}
	return &ProofNonces{source, scope, h}, nil
}
func (n *ProofNonces) NewNonce(ctx context.Context, scope grants.Scope) (string, string, error) {
	if scope != n.scope {
		return "", "", tokens.ErrInvalidCredential
	}
	m, err := n.source.NewMaterial(ctx)
	return m.RefreshSecret, m.RefreshHash, err
}
func (n *ProofNonces) HashNonce(scope grants.Scope, raw string) (string, error) {
	if scope != n.scope {
		return "", tokens.ErrInvalidCredential
	}
	return n.hasher.Digest(scope, "dpop_nonce", raw)
}
