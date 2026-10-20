package resource_test

import (
	"encoding/json"
	"errors"
	"github.com/startificial/mayi/pkg/resource"
	"net/http/httptest"
	"strings"
	"testing"
)

func metadata(t *testing.T, audience string) *resource.MetadataHandler {
	t.Helper()
	h, err := resource.NewMetadata(resource.MetadataConfig{Issuer: "https://auth.example/t/a", Audience: audience, Name: "Example API", PermissionScopes: []string{"read", "write"}, AuthorizationDetailTypes: []string{"https://api.example/types/document/v1"}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestResourceMetadataKeepsEachAudienceAndTrustedIssuer(t *testing.T) {
	for _, audience := range []string{"https://api.example", "https://api.example/tenant/a", "https://api.example/tenant/b", "https://api.example/tenant/a/", "https://api.example/a%2Fb"} {
		h := metadata(t, audience)
		want := strings.Replace(audience, "https://api.example", "https://api.example/.well-known/oauth-protected-resource", 1)
		if h.MetadataURL() != want {
			t.Fatal("wrong metadata URL", h.MetadataURL())
		}
		r := httptest.NewRequest("GET", h.MetadataURL(), nil)
		r.Host = "attacker.example"
		r.Header.Set("X-Forwarded-Host", "evil.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var d map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &d) != nil || d["resource"] != audience || strings.Contains(w.Body.String(), "attacker") || strings.Contains(w.Body.String(), "evil") || strings.Contains(w.Body.String(), "dpop_") || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("incorrect advertised metadata", w.Code, w.Body.String())
		}
		if d["authorization_servers"].([]any)[0] != "https://auth.example/t/a" || d["bearer_methods_supported"].([]any)[0] != "header" {
			t.Fatal("wrong advertised capabilities")
		}
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(method, h.MetadataURL(), nil))
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
				t.Fatal("method accepted", method)
			}
		}
		for _, path := range []string{h.MetadataURL() + "?token=secret", h.MetadataURL() + "?", "https://api.example/.well-known/oauth-protected-resource/wrong"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if w.Code != 404 {
				t.Fatal("metadata route mismatch accepted", path)
			}
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("HEAD", h.MetadataURL(), nil))
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("HEAD response")
		}
	}
}

func TestResourceChallengesAreSafeAndHaveDistinctRecovery(t *testing.T) {
	h := metadata(t, "https://api.example/tenant/a")
	for _, test := range []struct {
		err    error
		scopes []string
		status int
		code   string
	}{
		{nil, nil, 401, ""},
		{errors.Join(resource.ErrDenied, resource.ErrMissingCredential), nil, 401, ""},
		{errors.Join(resource.ErrDenied, resource.ErrInvalidRequest), nil, 400, "invalid_request"},
		{resource.ErrDenied, nil, 401, "invalid_token"},
		{errors.Join(resource.ErrDenied, resource.ErrInsufficientScope), []string{"write"}, 403, "insufficient_scope"},
		{resource.ErrUnavailable, nil, 503, "temporarily_unavailable"},
		{errors.New("raw token=secret or database failure"), nil, 500, "server_error"},
		{resource.ErrInsufficientScope, []string{"private-object-exists"}, 500, "server_error"},
		{resource.ErrInsufficientScope, []string{"read\"\r\nX-Secret:secret"}, 500, "server_error"},
	} {
		w := httptest.NewRecorder()
		h.WriteChallenge(w, test.err, test.scopes...)
		challenge := w.Header().Get("WWW-Authenticate")
		if w.Code != test.status || strings.Contains(w.Body.String()+challenge, "secret") || strings.Contains(challenge, "private-object") || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("unsafe response", w.Code, w.Body.String(), challenge)
		}
		if test.status == 400 || test.status == 401 || test.status == 403 {
			if !strings.Contains(challenge, `resource_metadata="`+h.MetadataURL()+`"`) {
				t.Fatal("no discovery challenge", challenge)
			}
			if test.code == "" && (strings.Contains(challenge, "error=") || w.Body.Len() != 0) {
				t.Fatal("missing credential disclosed error")
			}
			if test.status == 403 && !strings.Contains(challenge, `scope="write"`) {
				t.Fatal("no public scope hint")
			}
		} else if challenge != "" {
			t.Fatal("dependency/callback failure disguised as invalid token")
		}
		if test.code != "" && !strings.Contains(w.Body.String(), `"error":"`+test.code+`"`) {
			t.Fatal("wrong recovery code")
		}
	}
}

func TestResourceMetadataRejectsUntrustedConfigurationAndSnapshotsSlices(t *testing.T) {
	base := resource.MetadataConfig{Issuer: "https://auth.example/t/a", Audience: "https://api.example", Name: "API", PermissionScopes: []string{"read"}, AuthorizationDetailTypes: []string{"https://api.example/types/document/v1"}}
	for _, mutate := range []func(*resource.MetadataConfig){
		func(c *resource.MetadataConfig) { c.Issuer = "http://auth.example" },
		func(c *resource.MetadataConfig) { c.Audience = "https://user@api.example" },
		func(c *resource.MetadataConfig) { c.Audience = "https://api.example?q=token" },
		func(c *resource.MetadataConfig) { c.Name = "" },
		func(c *resource.MetadataConfig) { c.PermissionScopes = []string{"read\"injected"} },
		func(c *resource.MetadataConfig) { c.AuthorizationDetailTypes = []string{"unknown"} },
	} {
		c := base
		mutate(&c)
		if _, err := resource.NewMetadata(c); !errors.Is(err, resource.ErrUnavailable) {
			t.Fatal("invalid configuration accepted")
		}
	}
	h, err := resource.NewMetadata(base)
	if err != nil {
		t.Fatal(err)
	}
	base.PermissionScopes[0] = "evil"
	base.AuthorizationDetailTypes[0] = "evil"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", h.MetadataURL(), nil))
	if strings.Contains(w.Body.String(), "evil") {
		t.Fatal("mutable metadata alias")
	}
}

func TestResourceCredentialTransportSelectsSafeChallenge(t *testing.T) {
	h := metadata(t, "https://api.example")
	for _, test := range []struct {
		header, query, body string
		duplicate           bool
		status              int
	}{
		{status: 401},
		{query: "?access_token=secret", status: 400},
		{body: "access_token=secret", status: 400},
		{header: "Bearer secret", duplicate: true, status: 400},
		{header: "Bearer secret extra", status: 400},
		{header: "Basic secret", status: 400},
	} {
		r := httptest.NewRequest("GET", "https://api.example/documents/123"+test.query, strings.NewReader(test.body))
		if test.header != "" {
			r.Header.Set("Authorization", test.header)
		}
		if test.duplicate {
			r.Header.Add("Authorization", test.header)
		}
		if test.body != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		_, err := resource.HeaderToken(r)
		if err == nil {
			t.Fatal("invalid transport accepted")
		}
		w := httptest.NewRecorder()
		h.WriteChallenge(w, err)
		if w.Code != test.status || strings.Contains(w.Body.String()+w.Header().Get("WWW-Authenticate"), "secret") {
			t.Fatal("incorrect transport challenge", w.Code)
		}
		if test.status == 401 && strings.Contains(w.Header().Get("WWW-Authenticate"), "error=") {
			t.Fatal("missing auth has error")
		}
	}
}
