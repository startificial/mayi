package signing

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/health"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.IdentitySigner = (*Ring)(nil)
var _ tokens.Signer = (*Ring)(nil)
var _ administration.KeyCatalog = (*Ring)(nil)
var _ health.Signer = (*Ring)(nil)

// Ring contains only startup-verified remote signers. The database chooses the
// active version; unknown versions fail closed. Entries are immutable after New.
type Ring struct {
	scope    grants.Scope
	versions map[int]*Transit
	active   tokens.ActiveKeyReader
}

func NewRing(scope grants.Scope, versions []*Transit, active tokens.ActiveKeyReader) (*Ring, error) {
	if !scope.Valid() || len(versions) == 0 || len(versions) > 16 || active == nil {
		return nil, tokens.ErrUnavailable
	}
	r := &Ring{scope: scope, versions: map[int]*Transit{}, active: active}
	var keyName string
	for _, s := range versions {
		if s == nil || s.config.Scope != scope || r.versions[s.config.Version] != nil || keyName != "" && keyName != s.config.Key {
			return nil, tokens.ErrUnavailable
		}
		keyName = s.config.Key
		r.versions[s.config.Version] = s
	}
	return r, nil
}
func (r *Ring) PublicKey(_ context.Context, scope grants.Scope, version int) (identity.PublicKey, error) {
	s := r.versions[version]
	if scope != r.scope || s == nil {
		return identity.PublicKey{}, tokens.ErrUnavailable
	}
	// JOSE's validated public JWK owns the standard coordinate encoding.
	key, ok := s.public.Key.(*ecdsa.PublicKey)
	if !ok {
		return identity.PublicKey{}, tokens.ErrUnavailable
	}
	return identity.PublicKey{ID: s.public.KeyID, Version: version, X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}, nil
}
func (r *Ring) SignAccessToken(ctx context.Context, c domain.AccessClaims) (string, error) {
	if c.Scope != r.scope {
		return "", tokens.ErrUnavailable
	}
	version := c.SigningKeyVersion
	if version == 0 {
		var err error
		version, err = r.active.ActiveSigningKey(ctx, r.scope)
		if err != nil {
			return "", tokens.ErrUnavailable
		}
	}
	s := r.versions[version]
	if s == nil {
		return "", tokens.ErrUnavailable
	}
	return s.SignAccessToken(ctx, c)
}

// Check verifies remote availability, credential validity and key safety without
// producing a token or exporting private material.
func (r *Ring) Check(ctx context.Context, scope grants.Scope, version int) error {
	s := r.versions[version]
	if scope != r.scope || s == nil {
		return tokens.ErrUnavailable
	}
	fresh, err := New(ctx, s.config, s.client)
	if err != nil {
		return tokens.ErrUnavailable
	}
	if version < fresh.minimumVersion || !fresh.public.Key.(*ecdsa.PublicKey).Equal(s.public.Key) {
		return tokens.ErrUnavailable
	}
	return nil
}

func (r *Ring) SignIdentityToken(ctx context.Context, c domain.IdentityClaims) (string, error) {
	if c.Scope != r.scope || c.SigningKeyVersion < 1 || r.versions[c.SigningKeyVersion] == nil {
		return "", tokens.ErrUnavailable
	}
	return r.versions[c.SigningKeyVersion].SignIdentityToken(ctx, c)
}
