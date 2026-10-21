package egress

import (
	"context"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/services/administration"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func validMetadataBody() string {
	return `{"client_id":"https://agent.example/client.json","client_name":"Agent","token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"redirect_uris":["https://agent.example/cb"]}`
}

type metadataHTTP func(*http.Request) (*http.Response, error)

func (f metadataHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestCIMDTransportParsingCachingAndConditionalRequests(t *testing.T) {
	id := "https://agent.example/client.json"
	calls := 0
	c := &http.Client{Transport: metadataHTTP(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != id || r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("unexpected metadata request")
		}
		h := http.Header{"Content-Type": []string{"application/json"}, "Cache-Control": []string{"max-age=120"}, "Etag": []string{`"v1"`}}
		if calls == 2 {
			if r.Header.Get("If-None-Match") != `"v1"` {
				t.Fatal("missing conditional request")
			}
			h.Set("Cache-Control", "no-store")
			return &http.Response{StatusCode: 304, Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(validMetadataBody()))}, nil
	})}
	r, err := fetchMetadata(context.Background(), c, id, administration.MetadataValidators{})
	if err != nil || r.Document.ClientID != id || r.FreshFor <= 0 || r.FreshFor > 120*time.Second || r.NoStore {
		t.Fatal("valid response failed", err)
	}
	r, err = fetchMetadata(context.Background(), c, id, r.Validators)
	if err != nil || !r.NotModified || !r.NoStore || r.FreshFor != 0 {
		t.Fatal("conditional no-store failed", err)
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		cc, age string
		store   bool
		fresh   time.Duration
	}{{"max-age=60", "30", false, 30 * time.Second}, {"max-age=999999999999999999", "0", false, 0}, {"max-age=60", "999999999999999999", false, 0}, {"max-age=3600", "0", false, 5 * time.Minute}, {"no-cache, max-age=60", "0", false, 0}, {"private, max-age=60", "0", true, 0}, {"no-store, max-age=60", "0", true, 0}, {"max-age=60, max-age=120", "0", false, 0}, {"s-maxage=20, max-age=120", "0", false, 20 * time.Second}} {
		h := http.Header{}
		h.Set("Cache-Control", test.cc)
		h.Set("Age", test.age)
		store, fresh := metadataCache(h, now, now)
		if store != test.store || fresh != test.fresh {
			t.Fatal("cache directive handling", test.cc, store, fresh)
		}
	}
}
func TestCIMDRejectsAmbiguousPrivateAndOversizedMetadata(t *testing.T) {
	valid := validMetadataBody()
	for _, bad := range []string{valid + "{}", strings.Replace(valid, `"client_name":"Agent"`, `"client_name":"Agent","Client_Name":"Other"`, 1), strings.Replace(valid, `"client_name":"Agent"`, `"client_secret":"secret"`, 1), strings.Replace(valid, `"none"`, `"client_secret_basic"`, 1), strings.Replace(valid, `"client_name":"Agent"`, `"jwks":{"keys":[]}`, 1), strings.Replace(valid, `"client_name":"Agent"`, `"client_name":null`, 1), strings.Replace(valid, `"refresh_token"`, `"client_credentials"`, 1), strings.Repeat("[", 17) + strings.Repeat("]", 17)} {
		if _, err := decodeMetadata([]byte(bad)); err == nil {
			t.Fatal("unsafe document parsed")
		}
	}
	id := "https://agent.example/client.json"
	for _, test := range []struct {
		status      int
		media, body string
	}{{302, "application/json", valid}, {304, "application/json", ""}, {200, "text/html", valid}, {200, "application/json", strings.Repeat("x", 32769)}, {200, "application/json", strings.Replace(valid, id, "https://other.example/client.json", 1)}} {
		c := &http.Client{Transport: metadataHTTP(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: test.status, Header: http.Header{"Content-Type": []string{test.media}}, Body: io.NopCloser(strings.NewReader(test.body))}, nil
		})}
		if _, err := fetchMetadata(context.Background(), c, id, administration.MetadataValidators{}); err == nil {
			t.Fatal("unsafe response accepted")
		}
	}
	for _, id := range []string{"https://127.0.0.1/client", "http://agent.example/client", "https://[::1]/client"} {
		if _, err := NewMetadata().FetchMetadata(context.Background(), id, administration.MetadataValidators{}); err == nil {
			t.Fatal("unsafe URL admitted")
		}
	}
	for _, raw := range []string{"::ffff:8.8.8.8", "::ffff:127.0.0.1", "169.254.169.254", "100.64.0.1", "2001:db8::1"} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Fatal("special address admitted")
		}
	}
	if _, ok := clients.MetadataURL(id); !ok {
		t.Fatal("fixture identity invalid")
	}
}
