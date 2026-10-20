package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.SecretHasher = (*SecretHasher)(nil)

type HashKey struct {
	Version int
	Key     []byte
	Active  bool
}
type SecretHasher struct {
	keys   map[int][]byte
	active int
}

func NewSecretHasher(keys []HashKey) (*SecretHasher, error) {
	h := &SecretHasher{keys: map[int][]byte{}}
	if len(keys) == 0 || len(keys) > 8 {
		return nil, tokens.ErrUnavailable
	}
	for _, key := range keys {
		if key.Version < 1 || key.Version > 9999 || len(key.Key) != 32 || h.keys[key.Version] != nil || key.Active && h.active != 0 {
			return nil, tokens.ErrUnavailable
		}
		h.keys[key.Version] = append([]byte(nil), key.Key...)
		if key.Active {
			h.active = key.Version
		}
	}
	if h.active == 0 {
		return nil, tokens.ErrUnavailable
	}
	return h, nil
}
func (h *SecretHasher) Prefix(secret string) string {
	return "v" + strconv.Itoa(h.active) + "." + secret
}
func (h *SecretHasher) Digest(scope grants.Scope, purpose, raw string) (string, error) {
	prefix, secret, ok := strings.Cut(raw, ".")
	version, err := strconv.Atoi(strings.TrimPrefix(prefix, "v"))
	b, decode := base64.RawURLEncoding.DecodeString(secret)
	if !scope.Valid() || !ok || err != nil || prefix != "v"+strconv.Itoa(version) || h.keys[version] == nil || decode != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != secret || purpose != "authorization_code" && purpose != "refresh_token" && purpose != "access_token" && purpose != "client_secret" && purpose != "dpop_nonce" {
		return "", tokens.ErrInvalidCredential
	}
	mac := hmac.New(sha256.New, h.keys[version])
	for _, s := range []string{"mayi-credential", prefix, scope.TenantID, scope.Issuer, purpose, raw} {
		mac.Write([]byte(s))
		mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}
