package crypto

import (
	"context"
	"github.com/startificial/mayi/internal/services/authorization"
)

var _ authorization.MaterialSource = (*AuthorizationSource)(nil)

type AuthorizationSource struct{ material *MaterialSource }

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
