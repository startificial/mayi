package middleware

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authentication"
	"net/http"
	"net/http/httptest"
	"testing"
)

type admissionProbe struct {
	key string
	err error
}

func (p *admissionProbe) Check(_ context.Context, _ grants.Scope, _, _, key string) error {
	p.key = key
	return p.err
}
func TestAdmissionTrustsOnlyExplicitProxyChain(t *testing.T) {
	p := &admissionProbe{}
	a, err := NewAdmission(p, []string{"127.0.0.0/8", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		peer, forward, want string
		status              int
	}{
		{"192.0.2.8:42", "198.51.100.2", "192.0.2.8", 204},
		{"127.0.0.1:42", "198.51.100.2, 10.0.0.2", "198.51.100.2", 204},
		{"127.0.0.1:42", "203.0.113.1, 198.51.100.2", "198.51.100.2", 204},
		{"127.0.0.1:42", "bad input", "", 400},
		{"bad peer", "198.51.100.2", "", 400},
	} {
		r := httptest.NewRequest("POST", "https://auth.example/t/a/token", nil)
		r.RemoteAddr = c.peer
		r.Header.Set("X-Forwarded-For", c.forward)
		w := httptest.NewRecorder()
		called := false
		p.key = ""
		a.Protect(grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, "token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })).ServeHTTP(w, r)
		if w.Code != c.status || c.status == 204 && p.key != c.want || c.status != 204 && called {
			t.Fatal(c, w.Code, p.key, called)
		}
	}
	for _, failure := range []struct {
		err    error
		status int
		retry  string
	}{{&authentication.LimitError{RetryAfterSeconds: 60}, 429, "60"}, {errors.New("state unavailable"), 503, ""}} {
		p.err = failure.err
		r := httptest.NewRequest("POST", "https://auth.example/t/a/token", nil)
		r.RemoteAddr = "192.0.2.8:42"
		w := httptest.NewRecorder()
		a.Protect(grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, "token", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("denied request reached handler") })).ServeHTTP(w, r)
		if w.Code != failure.status || w.Header().Get("Retry-After") != failure.retry {
			t.Fatal(w.Code, w.Header())
		}
	}
}
