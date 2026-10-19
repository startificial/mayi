package crypto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.MaterialSource = (*MaterialSource)(nil)

type MaterialSource struct {
	scope   grants.Scope
	hasher  *SecretHasher
	purpose string
}

func NewMaterialSource() *MaterialSource { return &MaterialSource{} }
func NewKeyedMaterialSource(scope grants.Scope, h *SecretHasher, purpose string) (*MaterialSource, error) {
	if !scope.Valid() || h == nil {
		return nil, tokens.ErrUnavailable
	}
	return &MaterialSource{scope: scope, hasher: h, purpose: purpose}, nil
}
func (s *MaterialSource) NewMaterial(ctx context.Context) (tokens.Material, error) {
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
	digest := hex.EncodeToString(hash[:])
	if s.hasher != nil {
		secret = s.hasher.Prefix(secret)
		var err error
		digest, err = s.hasher.Digest(s.scope, s.purpose, secret)
		if err != nil {
			return tokens.Material{}, err
		}
	}
	m := tokens.Material{ID: hex.EncodeToString(entropy[:16]), RefreshSecret: secret, RefreshHash: digest}
	if s.hasher != nil && s.purpose == "refresh_token" {
		var extra [32]byte
		if _, err := rand.Read(extra[:]); err != nil {
			return tokens.Material{}, tokens.ErrUnavailable
		}
		m.AccessSecret = s.hasher.Prefix(base64.RawURLEncoding.EncodeToString(extra[:]))
		var err error
		m.AccessHash, err = s.hasher.Digest(s.scope, "access_token", m.AccessSecret)
		if err != nil {
			return tokens.Material{}, err
		}
	}
	return m, nil
}

func (*MaterialSource) DigestAccessToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
