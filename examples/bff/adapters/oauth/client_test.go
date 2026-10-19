package oauth_test

import (
	"context"
	"github.com/startificial/mayi/examples/bff/adapters/oauth"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRefreshUsesFixedResourceAndNeverRetries(t *testing.T) {
	calls := 0
	fail := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/token" || r.ParseForm() != nil || r.PostForm.Get("resource") != "https://api.example" || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "old" {
			t.Error("invalid audience/refresh request")
		}
		client, secret, ok := r.BasicAuth()
		if !ok || client != "web" || secret != "secret" {
			t.Error("missing fixed basic authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		if fail {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"access","refresh_token":"next","token_type":"Bearer","expires_in":300}`))
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := oauth.New(server.URL, "web", "secret", "https://app.example/cb", "https://api.example", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	if token, err := client.Refresh(context.Background(), "old"); err != nil || token.Refresh != "next" {
		t.Fatal("refresh", err)
	}
	fail = true
	if token, err := client.Refresh(context.Background(), "old"); err == nil || token.Access != "" {
		t.Fatal("uncertain response accepted")
	}
	if calls != 2 {
		t.Fatal("refresh was automatically retried", calls)
	}
}
