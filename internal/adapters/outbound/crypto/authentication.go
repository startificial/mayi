package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/startificial/mayi/internal/services/authentication"
)

var _ authentication.Secrets = (*LoginSecrets)(nil)

type LoginSecrets struct{ material *MaterialSource }

func NewLoginSecrets() *LoginSecrets { return &LoginSecrets{NewMaterialSource()} }
func (s *LoginSecrets) NewSecret(ctx context.Context) (string, error) {
	m, err := s.material.NewMaterial(ctx)
	return m.RefreshSecret, err
}
func (*LoginSecrets) Digest(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}
