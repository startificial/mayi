package signing_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/adapters/outbound/signing"
	"github.com/startificial/mayi/internal/domain/grants"
)

func TestTransitRejectsUnsafeMetadata(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	for _, mode := range []string{"missing exportability", "missing backup flag", "exportable", "backup", "wrong algorithm", "private PEM", "wrong version", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			data := map[string]any{"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false, "keys": map[string]any{"1": map[string]string{"public_key": public}}}
			switch mode {
			case "missing exportability":
				delete(data, "exportable")
			case "missing backup flag":
				delete(data, "allow_plaintext_backup")
			case "exportable":
				data["exportable"] = true
			case "backup":
				data["allow_plaintext_backup"] = true
			case "wrong algorithm":
				data["type"] = "rsa-2048"
			case "private PEM":
				data["keys"] = map[string]any{"1": map[string]string{"public_key": "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"}}
			case "wrong version":
				data["keys"] = map[string]any{"2": map[string]string{"public_key": public}}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, "https://example.invalid", 302)
					return
				}
				if r.Header.Get("X-Vault-Token") != "fixture-token" {
					t.Error("missing service authentication")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
			}))
			defer server.Close()
			_, err := signing.New(context.Background(), signing.Config{Address: server.URL, Key: "key", Token: "fixture-token", Version: 1, Scope: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, AllowLoopbackHTTP: true}, &http.Client{Timeout: time.Second})
			if err == nil {
				t.Fatal("unsafe signer configuration accepted")
			}
		})
	}
}
func TestTransitRejectsUnboundedClientAndUntrustedURL(t *testing.T) {
	c := signing.Config{Address: "http://example.com", Key: "key", Token: "fixture", Version: 1, Scope: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, AllowLoopbackHTTP: true}
	if _, err := signing.New(context.Background(), c, &http.Client{Timeout: time.Second}); err == nil {
		t.Fatal("non-loopback HTTP accepted")
	}
	c.Address = "https://example.com"
	if _, err := signing.New(context.Background(), c, &http.Client{}); err == nil {
		t.Fatal("unbounded HTTP client accepted")
	}
	c.Address = "https://example.com?token=untrusted"
	if _, err := signing.New(context.Background(), c, &http.Client{Timeout: time.Second}); err == nil {
		t.Fatal("URL query accepted")
	}
}
