package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestDestinationPolicy(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "::ffff:127.0.0.1", "2001:db8::1", "2002:7f00:1::1", "0.0.0.0", "198.18.0.1", "fc00::1", "fe80::1", "240.0.0.1"} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Fatal("unsafe destination", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(raw)) {
			t.Fatal("public destination refused", raw)
		}
	}
	for _, raw := range []string{"http://public.example/jwks", "https://user:password@public.example/jwks", "https://public.example/jwks#x", "https://public.example/jwks?x=1", "https://public.example:8443/jwks"} {
		if _, err := New(Config{URLs: []string{raw}}); err == nil {
			t.Fatal("unsafe configuration accepted", raw)
		}
	}
}
func TestRedirectPrivateAddressAndResponseBounds(t *testing.T) {
	hits := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/secret", 302)
		case "/huge":
			_, _ = w.Write([]byte(strings.Repeat("x", 1<<20+1)))
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer s.Close()
	urls := []string{s.URL + "/ok", s.URL + "/redirect", s.URL + "/huge", s.URL + "/html"}
	c, err := New(Config{URLs: urls, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.GetJSON(context.Background(), urls[0]); err != nil {
		t.Fatal(err)
	}
	for _, raw := range urls[1:] {
		if _, err = c.GetJSON(context.Background(), raw); err == nil {
			t.Fatal("unsafe response accepted", raw)
		}
	}
	if hits != 4 {
		t.Fatal("redirect followed", hits)
	}
	if _, err = c.GetJSON(context.Background(), s.URL+"/secret"); err == nil || hits != 4 {
		t.Fatal("unlisted destination fetched")
	}
	c, err = New(Config{URLs: []string{"https://127.0.0.1/jwks"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.GetJSON(context.Background(), "https://127.0.0.1/jwks"); err == nil {
		t.Fatal("private HTTPS accepted")
	}
}

func TestMixedDNSAnswersAndRebindingFailClosed(t *testing.T) {
	public := netip.MustParseAddr("8.8.8.8")
	private := netip.MustParseAddr("127.0.0.1")
	if !safeAnswers("idp.example", "443", []netip.Addr{public}, false) {
		t.Fatal("valid public answer refused")
	}
	for _, ips := range [][]netip.Addr{nil, {public, private}, {private}} {
		if safeAnswers("idp.example", "443", ips, false) {
			t.Fatal("private/mixed/rebound DNS accepted")
		}
	}
	if safeAnswers("localhost", "1234", []netip.Addr{private}, true) {
		t.Fatal("development exception accepted a DNS hostname")
	}
	if !safeAnswers("127.0.0.1", "1234", []netip.Addr{private}, true) {
		t.Fatal("explicit local fixture refused")
	}
}
