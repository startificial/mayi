package crypto

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.ProofVerifier = (*DPoP)(nil)

type DPoP struct{}

func NewDPoP() *DPoP { return &DPoP{} }
func (*DPoP) VerifyProof(ctx context.Context, r tokens.ProofRequest, now time.Time) (tokens.VerifiedProof, error) {
	invalid := tokens.ErrInvalidCredential
	if ctx.Err() != nil || now.IsZero() || len(r.JWT) > 8192 || !strictDPoP(r.JWT) {
		return tokens.VerifiedProof{}, invalid
	}
	jws, err := jose.ParseSigned(r.JWT, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(jws.Signatures) != 1 {
		return tokens.VerifiedProof{}, invalid
	}
	h := jws.Signatures[0].Protected
	if h.ExtraHeaders["typ"] != "dpop+jwt" || h.JSONWebKey == nil || !h.JSONWebKey.IsPublic() || h.Algorithm != "ES256" || len(jws.Signatures[0].Unprotected.ExtraHeaders) > 0 || jws.Signatures[0].Unprotected.JSONWebKey != nil {
		return tokens.VerifiedProof{}, invalid
	}
	key, ok := h.JSONWebKey.Key.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !h.JSONWebKey.Valid() || h.JSONWebKey.Algorithm != "" && h.JSONWebKey.Algorithm != "ES256" || h.JSONWebKey.Use != "" && h.JSONWebKey.Use != "sig" {
		return tokens.VerifiedProof{}, invalid
	}
	for _, name := range []jose.HeaderKey{"jku", "x5u", "crit"} {
		if _, ok := h.ExtraHeaders[name]; ok {
			return tokens.VerifiedProof{}, invalid
		}
	}
	payload, err := jws.Verify(h.JSONWebKey)
	if err != nil {
		return tokens.VerifiedProof{}, invalid
	}
	var c struct {
		ID     string `json:"jti"`
		IAT    int64  `json:"iat"`
		Method string `json:"htm"`
		URL    string `json:"htu"`
		ATH    string `json:"ath"`
		Nonce  string `json:"nonce"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return tokens.VerifiedProof{}, invalid
	}
	actual, targetOK := domain.ProofTarget(c.URL, true)
	expectedTarget, expectedOK := domain.ProofTarget(r.URL, false)
	if !targetOK || !expectedOK || actual != expectedTarget || len(c.ID) < 16 || len(c.ID) > 256 || c.Method != r.Method || r.Nonce != "" && c.Nonce != r.Nonce || len(c.Nonce) > 128 || c.IAT < now.Add(-time.Minute).Unix() || c.IAT > now.Add(5*time.Second).Unix() {
		return tokens.VerifiedProof{}, invalid
	}
	for _, ch := range c.ID {
		if ch < 0x21 || ch > 0x7e {
			return tokens.VerifiedProof{}, invalid
		}
	}
	expected := ""
	if r.AccessToken != "" {
		digest := sha256.Sum256([]byte(r.AccessToken))
		expected = base64.RawURLEncoding.EncodeToString(digest[:])
	}
	if c.ATH != expected {
		return tokens.VerifiedProof{}, invalid
	}
	thumb, err := h.JSONWebKey.Thumbprint(stdcrypto.SHA256)
	if err != nil {
		return tokens.VerifiedProof{}, invalid
	}
	return tokens.VerifiedProof{ID: c.ID, Nonce: c.Nonce, Thumbprint: base64.RawURLEncoding.EncodeToString(thumb), ExpiresAt: time.Unix(c.IAT, 0).Add(65 * time.Second)}, nil
}

func strictDPoP(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	fields, ok := clientObject(header, "alg", "typ", "jwk")
	if !ok || len(fields) != 3 {
		return false
	}
	if _, ok = clientObject(fields["jwk"], "kty", "crv", "x", "y", "alg", "use", "kid"); !ok {
		return false
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	values, ok := clientObject(claims, "jti", "iat", "htm", "htu", "ath", "nonce")
	if !ok {
		return false
	}
	for name, raw := range values {
		if string(raw) == "null" {
			return false
		}
		if name != "iat" {
			var value string
			if json.Unmarshal(raw, &value) != nil {
				return false
			}
		}
	}
	return true
}
