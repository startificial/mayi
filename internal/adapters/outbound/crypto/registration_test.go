package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"strings"
	"testing"
)

func TestInitialRegistrationCredentialsAreDistinctAndTenantBound(t *testing.T) {
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	token := strings.Repeat("x", 43)
	sum := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(sum[:])
	c, err := NewRegistrationCredentials(scope, digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", strings.Repeat("y", 43), token + "extra", strings.Repeat("!", 43)} {
		if ok, err := c.InitialAccess(context.Background(), scope, raw); err != nil || ok {
			t.Fatal("invalid credential accepted")
		}
	}
	if ok, err := c.InitialAccess(context.Background(), scope, token); err != nil || !ok {
		t.Fatal("valid credential rejected")
	}
	foreign := scope
	foreign.Issuer = "https://other.example/t/a"
	if ok, _ := c.InitialAccess(context.Background(), foreign, token); ok {
		t.Fatal("foreign issuer authenticated")
	}
	if _, err := c.NewClientID(context.Background(), foreign); err == nil {
		t.Fatal("foreign ID generated")
	}
	a, err := c.NewClientID(context.Background(), scope)
	if err != nil || !clients.ValidClientID(a) {
		t.Fatal("invalid generated client ID")
	}
	b, err := c.NewClientID(context.Background(), scope)
	if err != nil || a == b {
		t.Fatal("repeated client ID")
	}
	empty, _ := NewRegistrationCredentials(scope, "")
	if ok, _ := empty.InitialAccess(context.Background(), scope, token); ok {
		t.Fatal("unconfigured credential accepted")
	}
	for _, bad := range []string{"secret", strings.ToUpper(digest), digest + "00"} {
		if _, err := NewRegistrationCredentials(scope, bad); err == nil {
			t.Fatal("invalid digest accepted")
		}
	}
}
