package crypto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.MaterialSource = (*MaterialSource)(nil)

type MaterialSource struct{}

func NewMaterialSource() *MaterialSource { return &MaterialSource{} }
func (*MaterialSource) NewMaterial(ctx context.Context) (tokens.Material, error) {
	if ctx.Err() != nil {
		return tokens.Material{}, tokens.ErrUnavailable
	}
	var entropy [48]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return tokens.Material{}, tokens.ErrUnavailable
	}
	if ctx.Err() != nil {
		return tokens.Material{}, tokens.ErrUnavailable
	}
	secret := base64.RawURLEncoding.EncodeToString(entropy[16:])
	hash := sha256.Sum256([]byte(secret))
	return tokens.Material{ID: hex.EncodeToString(entropy[:16]), RefreshSecret: secret, RefreshHash: hex.EncodeToString(hash[:])}, nil
}
