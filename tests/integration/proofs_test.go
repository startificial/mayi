package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/services/tokens"
)

func proof(t *testing.T, key *ecdsa.PrivateKey, changes map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: &key.PublicKey}))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"jti": "proof-unique-123456789", "iat": time.Now().Unix(), "htm": "POST", "htu": "https://auth.example/t/a/token", "nonce": "nonce"}
	for k, v := range changes {
		claims[k] = v
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestRealDPoPBindingAndAtomicReplay(t *testing.T) {
	e := setup(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := cryptoadapter.NewSecretHasher([]cryptoadapter.HashKey{{Version: 1, Key: []byte("01234567890123456789012345678901"), Active: true}})
	if err != nil {
		t.Fatal(err)
	}
	nonces, err := cryptoadapter.NewProofNonces(e.scope, hasher)
	if err != nil {
		t.Fatal(err)
	}
	service, err := tokens.NewProofs(cryptoadapter.NewDPoP(), e.store, e.store, nonces, clock{})
	if err != nil {
		t.Fatal(err)
	}
	request := tokens.ProofRequest{JWT: proof(t, key, map[string]any{"nonce": ""}), Method: "POST", URL: "https://auth.example/t/a/token"}
	_, err = service.Verify(context.Background(), e.scope, request)
	var nonce *tokens.NonceChallenge
	if !errors.As(err, &nonce) {
		t.Fatal("expected nonce challenge", err)
	}
	request.JWT = proof(t, key, map[string]any{"nonce": nonce.Nonce})
	var group sync.WaitGroup
	results := make(chan string, 2)
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			thumb, _ := service.Verify(context.Background(), e.scope, request)
			results <- thumb
		}()
	}
	group.Wait()
	close(results)
	winner := ""
	count := 0
	for thumb := range results {
		if thumb != "" {
			winner = thumb
			count++
		}
	}
	if count != 1 {
		t.Fatalf("DPoP replay winners %d", count)
	}
	e.exec(t, `UPDATE mayi.credentials SET binding_thumbprint=$1 WHERE tenant_id='a' AND hash='code'`, winner)
	cmd := e.command("code")
	if _, err := e.service.Redeem(context.Background(), cmd); err == nil {
		t.Fatal("unverified binding accepted")
	}
	cmd.Caller.BindingThumbprint = winner
	if _, err := e.service.Redeem(context.Background(), cmd); err != nil {
		t.Fatal("verified DPoP binding did not reach issuance", err)
	}
}
func TestDPoPBoundaryRejectsPurposeTargetNonceAndATH(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := cryptoadapter.NewDPoP()
	for name, changes := range map[string]map[string]any{"method": {"htm": "GET"}, "url": {"htu": "https://evil.example/token"}, "stale": {"iat": time.Now().Add(-2 * time.Minute).Unix()}, "future": {"iat": time.Now().Add(time.Minute).Unix()}, "nonce": {"nonce": "wrong"}, "id": {"jti": "short"}, "ath": {"ath": "unrelated"}} {
		t.Run(name, func(t *testing.T) {
			r := tokens.ProofRequest{JWT: proof(t, key, changes), Method: "POST", URL: "https://auth.example/t/a/token", Nonce: "nonce"}
			if _, err := v.VerifyProof(context.Background(), r, time.Now()); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	digest := sha256.Sum256([]byte("access-token"))
	r := tokens.ProofRequest{JWT: proof(t, key, map[string]any{"ath": base64.RawURLEncoding.EncodeToString(digest[:]), "htu": "https://api.example/resource", "htm": "GET"}), Method: "GET", URL: "https://api.example/resource", AccessToken: "access-token", Nonce: "nonce"}
	if _, err := v.VerifyProof(context.Background(), r, time.Now()); err != nil {
		t.Fatal(err)
	}
	r.AccessToken = "copied-other-token"
	if _, err := v.VerifyProof(context.Background(), r, time.Now()); err == nil {
		t.Fatal("token substitution accepted")
	}
}
