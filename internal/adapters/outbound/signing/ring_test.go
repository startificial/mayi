package signing_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/startificial/mayi/internal/adapters/outbound/signing"
	"github.com/startificial/mayi/internal/domain/grants"
	domaintokens "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/health"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type fixedActiveKey struct{}

func (fixedActiveKey) ActiveSigningKey(context.Context, grants.Scope) (int, error) { return 1, nil }
func (fixedActiveKey) CheckHealth(context.Context) error                           { return nil }
func TestReadinessRejectsDisabledSigningVersion(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	var minimum atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false, "min_encryption_version": minimum.Load(), "latest_version": 2, "keys": map[string]any{"1": map[string]string{"public_key": pub}}}})
			return
		}
		http.Error(w, "key version is below minimum", 400)
	}))
	defer upstream.Close()
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	transit, err := signing.New(context.Background(), signing.Config{Address: upstream.URL, Key: "review", Token: "fixture", Version: 1, Scope: scope, AllowLoopbackHTTP: true}, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ring, err := signing.NewRing(scope, []*signing.Transit{transit}, fixedActiveKey{})
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := health.New(fixedActiveKey{}, fixedActiveKey{}, []health.TenantSigner{{Scope: scope, Signer: ring}})
	if err != nil {
		t.Fatal(err)
	}
	minimum.Store(2)
	if err := readiness.Ready(context.Background()); err == nil {
		t.Fatal("readiness accepted disabled signing version")
	}
	claims := domaintokens.AccessClaims{ID: "review", Scope: scope, GrantID: "grant", Revision: 1, Subject: "alice", PrincipalType: "user", ClientID: "web", Resource: "https://api.example", Scopes: []string{"read"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	if token, err := ring.SignAccessToken(context.Background(), claims); err == nil || token != "" {
		t.Fatal("signing succeeded", err)
	}
	minimum.Store(0)
	if err := readiness.Ready(context.Background()); err != nil {
		t.Fatal("allowed key was not ready", err)
	}
}
