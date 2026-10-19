package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/clients"
	"strings"
	"time"
)

var _ clients.Secrets = (*ClientSecrets)(nil)
var _ clients.AssertionVerifier = (*ClientAssertions)(nil)

type ClientSecrets struct {
	scope  grants.Scope
	hasher *SecretHasher
	source *MaterialSource
}

func NewClientSecrets(scope grants.Scope, h *SecretHasher) (*ClientSecrets, error) {
	m, err := NewKeyedMaterialSource(scope, h, "client_secret")
	if err != nil {
		return nil, err
	}
	return &ClientSecrets{scope, h, m}, nil
}
func (s *ClientSecrets) NewClientSecret(ctx context.Context) (string, string, error) {
	m, err := s.source.NewMaterial(ctx)
	return m.RefreshSecret, m.RefreshHash, err
}
func (s *ClientSecrets) DigestClientSecret(raw string) (string, error) {
	return s.hasher.Digest(s.scope, "client_secret", raw)
}
func (*ClientSecrets) Matches(a, b string) bool {
	return len(a) == 64 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type ClientAssertions struct{ keys clients.KeyTransport }

func NewClientAssertions(keys clients.KeyTransport) (*ClientAssertions, error) {
	if keys == nil {
		return nil, clients.ErrUnavailable
	}
	return &ClientAssertions{keys}, nil
}
func (v *ClientAssertions) VerifyClientAssertion(ctx context.Context, raw, client, audience, inline, uri string, now time.Time) (clients.Assertion, error) {
	if len(raw) > 16384 || !strictClientAssertion(raw) || audience == "" || now.IsZero() || (inline == "") == (uri == "") {
		return clients.Assertion{}, clients.ErrDenied
	}
	data := []byte(inline)
	if uri != "" {
		var err error
		data, err = v.keys.FetchKeys(ctx, uri)
		if err != nil {
			return clients.Assertion{}, clients.ErrUnavailable
		}
	}
	if len(data) > 32768 {
		return clients.Assertion{}, clients.ErrDenied
	}
	var keys jose.JSONWebKeySet
	if !strictClientKeys(data) || json.Unmarshal(data, &keys) != nil || !validClientKeySet(keys) {
		return clients.Assertion{}, clients.ErrDenied
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.PS256, jose.RS256})
	if err != nil || len(parsed.Headers) != 1 || parsed.Headers[0].KeyID == "" || parsed.Headers[0].JSONWebKey != nil {
		return clients.Assertion{}, clients.ErrDenied
	}
	for k := range parsed.Headers[0].ExtraHeaders {
		if k != "typ" {
			return clients.Assertion{}, clients.ErrDenied
		}
	}
	if typ, ok := parsed.Headers[0].ExtraHeaders["typ"]; ok && typ != "JWT" {
		return clients.Assertion{}, clients.ErrDenied
	}
	var c jwt.Claims
	found := false
	for _, key := range keys.Keys {
		if key.KeyID != parsed.Headers[0].KeyID || !key.Valid() || !key.IsPublic() || key.Use != "sig" || key.Algorithm != parsed.Headers[0].Algorithm {
			continue
		}
		if err := parsed.Claims(key.Key, &c); err == nil {
			found = true
			break
		}
	}
	if !found || c.Issuer != client || c.Subject != client || len(c.Audience) != 1 || c.Audience[0] != audience || c.ID == "" || len(c.ID) > 128 || strings.ContainsAny(c.ID, "\r\n\x00") || c.IssuedAt == nil || c.Expiry == nil || c.IssuedAt.Time().After(now.Add(5*time.Second)) || c.IssuedAt.Time().Before(now.Add(-time.Minute)) || !c.Expiry.Time().After(now) || c.Expiry.Time().After(c.IssuedAt.Time().Add(time.Minute)) || c.NotBefore != nil && c.NotBefore.Time().After(now) {
		return clients.Assertion{}, clients.ErrDenied
	}
	return clients.Assertion{ID: c.ID, ExpiresAt: c.Expiry.Time()}, nil
}

func validClientKeySet(keys jose.JSONWebKeySet) bool {
	if len(keys.Keys) == 0 || len(keys.Keys) > 8 {
		return false
	}
	seen := map[string]bool{}
	for _, k := range keys.Keys {
		if !k.Valid() || !k.IsPublic() || k.Use != "sig" || k.KeyID == "" || len(k.KeyID) > 128 || seen[k.KeyID] || strings.ContainsAny(k.KeyID, "\r\n\x00") {
			return false
		}
		seen[k.KeyID] = true
		switch key := k.Key.(type) {
		case *ecdsa.PublicKey:
			if key.Curve != elliptic.P256() || k.Algorithm != "ES256" {
				return false
			}
		case *rsa.PublicKey:
			if key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.E < 65537 || k.Algorithm != "PS256" && k.Algorithm != "RS256" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (v *ClientAssertions) ValidateKeys(ctx context.Context, inline, uri string) error {
	if (inline == "") == (uri == "") {
		return clients.ErrDenied
	}
	data := []byte(inline)
	if uri != "" {
		var err error
		data, err = v.keys.FetchKeys(ctx, uri)
		if err != nil {
			return clients.ErrUnavailable
		}
	}
	if len(data) > 32768 {
		return clients.ErrDenied
	}
	var keys jose.JSONWebKeySet
	if !strictClientKeys(data) || json.Unmarshal(data, &keys) != nil || !validClientKeySet(keys) {
		return clients.ErrDenied
	}
	return nil
}
