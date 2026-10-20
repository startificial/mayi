package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/startificial/mayi/internal/services/tokens"
	"testing"
	"time"
)

func TestDPoPStrictParsingRejectsAmbiguousClaimsAndKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: &key.PublicKey}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	base := fmt.Sprintf(`"jti":"unique-proof-id-123456","iat":%d,"htm":"POST","htu":"https://auth.example/t/a/token"`, now.Unix())
	for _, extra := range []string{`,"htm":"GET"`, `,"HTM":"POST"`, `,"nonce":null`, `,"nonce":123`, `,"ath":null`, `,"unknown":true`, `,"iat":1`, `,"jti":null`} {
		jws, err := signer.Sign([]byte("{" + base + extra + "}"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jws.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewDPoP().VerifyProof(context.Background(), tokens.ProofRequest{JWT: raw, Method: "POST", URL: "https://auth.example/t/a/token"}, now); err == nil {
			t.Fatal("ambiguous proof accepted", extra)
		}
	}
	for _, header := range []string{`{"typ":"dpop+jwt","typ":"dpop+jwt","alg":"ES256","jwk":{}}`, `{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","kty":"EC"}}`, `{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","d":"private"}}`, `{"typ":"dpop+jwt","alg":"ES256","jwk":{},"jku":"https://evil.example"}`} {
		raw := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte("{"+base+"}")) + ".signature"
		if strictDPoP(raw) {
			t.Fatal("ambiguous or private header accepted")
		}
	}
	jws, err := signer.Sign([]byte("{" + base + "}"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewDPoP().VerifyProof(context.Background(), tokens.ProofRequest{JWT: raw, Method: "POST", URL: "https://AUTH.example:443/t/a/token?ignored=query"}, now)
	if err != nil || result.Thumbprint == "" {
		t.Fatal("canonical endpoint comparison failed", err)
	}
}
