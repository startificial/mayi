package crypto

import (
	"context"
	stdcrypto "crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.ProofVerifier = (*DPoP)(nil)

type DPoP struct{}

func NewDPoP() *DPoP { return &DPoP{} }
func (*DPoP) VerifyProof(ctx context.Context, r tokens.ProofRequest, now time.Time) (tokens.VerifiedProof, error) {
	invalid := tokens.ErrInvalidCredential
	if ctx.Err() != nil || now.IsZero() || len(r.JWT) > 8192 || strings.Count(r.JWT, ".") != 2 {
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
	if json.Unmarshal(payload, &c) != nil || len(c.ID) < 16 || len(c.ID) > 256 || c.Method != r.Method || c.URL != r.URL || c.Nonce != r.Nonce || c.IAT < now.Add(-time.Minute).Unix() || c.IAT > now.Add(5*time.Second).Unix() {
		return tokens.VerifiedProof{}, invalid
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
	return tokens.VerifiedProof{ID: c.ID, Thumbprint: base64.RawURLEncoding.EncodeToString(thumb), ExpiresAt: time.Unix(c.IAT, 0).Add(65 * time.Second)}, nil
}
