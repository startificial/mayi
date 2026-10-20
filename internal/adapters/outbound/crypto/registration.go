package crypto

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
)

var _ administration.RegistrationCredentials = (*RegistrationCredentials)(nil)

type RegistrationCredentials struct {
	scope    grants.Scope
	digest   []byte
	material *MaterialSource
}

func NewRegistrationCredentials(scope grants.Scope, digest string) (*RegistrationCredentials, error) {
	if !scope.Valid() {
		return nil, administration.ErrInvalid
	}
	b, err := hex.DecodeString(digest)
	if err != nil || digest != "" && (len(b) != 32 || hex.EncodeToString(b) != digest) {
		return nil, administration.ErrInvalid
	}
	return &RegistrationCredentials{scope, b, NewMaterialSource()}, nil
}

func (c *RegistrationCredentials) InitialAccess(ctx context.Context, scope grants.Scope, raw string) (bool, error) {
	if ctx.Err() != nil {
		return false, administration.ErrUnavailable
	}
	if scope != c.scope || len(raw) != 43 || len(c.digest) != 32 {
		return false, nil
	}
	for _, r := range raw {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false, nil
		}
	}
	h := sha256.Sum256([]byte(raw))
	return subtle.ConstantTimeCompare(c.digest, h[:]) == 1, nil
}

func (c *RegistrationCredentials) NewClientID(ctx context.Context, scope grants.Scope) (string, error) {
	if scope != c.scope {
		return "", administration.ErrDenied
	}
	m, err := c.material.NewMaterial(ctx)
	if err != nil {
		return "", administration.ErrUnavailable
	}
	return "agent-" + m.ID, nil
}
