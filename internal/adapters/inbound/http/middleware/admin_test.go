package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementCredentialsAreHeaderOnlyAndTenantScoped(t *testing.T) {
	token := strings.Repeat("a", 43)
	digest := sha256.Sum256([]byte(token))
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	c, err := New([]Credential{{SHA256: hex.EncodeToString(digest[:]), Actor: administration.Actor{ID: "admin", Scope: scope, Permissions: []string{"policy:read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"none", "query", "cookie", "duplicate header", "wrong credential", "origin", "foreign tenant", "valid"} {
		t.Run(mode, func(t *testing.T) {
			called := false
			target := scope
			if mode == "foreign tenant" {
				target.TenantID = "b"
			}
			h := c.Protect(target, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if Actor(r).Scope != scope {
					t.Fatal("actor untrusted")
				}
				w.WriteHeader(204)
			}))
			r := httptest.NewRequest("GET", "https://auth.example/admin", nil)
			if mode == "query" {
				r.URL.RawQuery = "access_token=" + token
			}
			if mode == "cookie" {
				r.AddCookie(&http.Cookie{Name: "token", Value: token})
			}
			if mode == "valid" || mode == "foreign tenant" || mode == "origin" || mode == "duplicate header" {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			if mode == "duplicate header" {
				r.Header.Add("Authorization", "Bearer "+token)
			}
			if mode == "wrong credential" {
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 43))
			}
			if mode == "origin" {
				r.Header.Set("Origin", "https://evil.example")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "valid" {
				if w.Code != 204 || !called {
					t.Fatal("valid credential refused")
				}
			} else if called || w.Code < 400 {
				t.Fatal("unauthorized handler invoked")
			}
		})
	}
}
