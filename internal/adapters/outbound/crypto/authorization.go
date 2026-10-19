package crypto

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authorization"
)

var _ authorization.MaterialSource = (*AuthorizationSource)(nil)

type AuthorizationSource struct {
	material *MaterialSource
	code     *MaterialSource
}

func NewAuthorizationSource() *AuthorizationSource {
	return &AuthorizationSource{material: NewMaterialSource()}
}
func (s *AuthorizationSource) NewAuthorizationMaterial(ctx context.Context) (authorization.Material, error) {
	m, err := s.material.NewMaterial(ctx)
	if err != nil {
		return authorization.Material{}, authorization.ErrUnavailable
	}
	return authorization.Material{ID: m.ID, Secret: m.RefreshSecret, Hash: m.RefreshHash}, nil
}

func NewKeyedAuthorizationSource(scope grants.Scope, h *SecretHasher) (*AuthorizationSource, error) {
	code, err := NewKeyedMaterialSource(scope, h, "authorization_code")
	if err != nil {
		return nil, err
	}
	return &AuthorizationSource{material: NewMaterialSource(), code: code}, nil
}
func (s *AuthorizationSource) NewCodeMaterial(ctx context.Context, scope grants.Scope) (authorization.Material, error) {
	if s.code == nil {
		return s.NewAuthorizationMaterial(ctx)
	}
	if s.code.scope != scope {
		return authorization.Material{}, authorization.ErrUnavailable
	}
	m, err := s.code.NewMaterial(ctx)
	return authorization.Material{ID: m.ID, Secret: m.RefreshSecret, Hash: m.RefreshHash}, err
}
