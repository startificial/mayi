// Package crypto adapts reviewed standard-library primitives to service ports.
package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	"github.com/startificial/mayi/internal/services/tokens"
)

var ErrInvalidPKCE = errors.New("invalid S256 proof")
var _ tokens.PKCEVerifier = (*PKCE)(nil)

type PKCE struct{}

func New() *PKCE { return &PKCE{} }

// VerifyS256 follows RFC 7636 sections 4.1 and 4.6. There is no plain method.
func (*PKCE) VerifyS256(challenge, verifier string) error {
	if len(challenge) != 43 || len(verifier) < 43 || len(verifier) > 128 {
		return ErrInvalidPKCE
	}
	for _, c := range []byte(verifier) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
			return ErrInvalidPKCE
		}
	}
	digest := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) != 1 {
		return ErrInvalidPKCE
	}
	return nil
}
