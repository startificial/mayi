package crypto_test

import (
	"context"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
	"strings"
	"testing"
)

func TestCredentialDigestsSeparateContextAndRetainVersions(t *testing.T) {
	key := []byte(strings.Repeat("a", 32))
	hasher, err := cryptoadapter.NewSecretHasher([]cryptoadapter.HashKey{{Version: 1, Key: key}, {Version: 2, Key: []byte(strings.Repeat("b", 32)), Active: true}})
	if err != nil {
		t.Fatal(err)
	}
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	raw := "v1." + strings.Repeat("A", 43)
	original, err := hasher.Digest(scope, "refresh_token", raw)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{original: true}
	for _, c := range []struct {
		scope        grants.Scope
		purpose, raw string
	}{{grants.Scope{TenantID: "b", Issuer: scope.Issuer}, "refresh_token", raw}, {grants.Scope{TenantID: "a", Issuer: "https://other.example/t/a"}, "refresh_token", raw}, {scope, "authorization_code", raw}, {scope, "client_secret", raw}, {scope, "access_token", raw}, {scope, "refresh_token", "v2." + strings.Repeat("A", 43)}} {
		digest, err := hasher.Digest(c.scope, c.purpose, c.raw)
		if err != nil || seen[digest] {
			t.Fatal("credential contexts collided", err)
		}
		seen[digest] = true
	}
	clear(key)
	if got, err := hasher.Digest(scope, "refresh_token", raw); err != nil || got != original {
		t.Fatal("caller mutated retained key")
	}
	for _, bad := range []string{strings.TrimPrefix(raw, "v1."), "v01." + strings.Repeat("A", 43), "v3." + strings.Repeat("A", 43), raw + "=", raw + "extra"} {
		if _, err := hasher.Digest(scope, "refresh_token", bad); err == nil {
			t.Fatal("noncanonical credential accepted")
		}
	}
	material, err := cryptoadapter.NewKeyedMaterialSource(scope, hasher, tokens.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := material.NewMaterial(context.Background())
	if err != nil || !strings.HasPrefix(fresh.RefreshSecret, "v2.") || fresh.RefreshSecret == fresh.AccessSecret || fresh.RefreshHash == fresh.AccessHash {
		t.Fatal("credential issuance separation", err)
	}
	retired, _ := cryptoadapter.NewSecretHasher([]cryptoadapter.HashKey{{Version: 2, Key: []byte(strings.Repeat("b", 32)), Active: true}})
	if _, err := retired.Digest(scope, "refresh_token", raw); err == nil {
		t.Fatal("removed key remained usable")
	}
}
