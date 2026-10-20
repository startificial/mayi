package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/authorization"
)

func TestP3NativeCallbacksPersistAndPinTheRequestedRedirect(t *testing.T) {
	for _, test := range []struct {
		name, registered, requested string
		forbidden                   []string
	}{
		{"ipv4", "http://127.0.0.1/cb?provider=mayi", "http://127.0.0.1:54321/cb?provider=mayi", []string{"http://127.0.0.1:54321/other?provider=mayi", "http://[::1]:54321/cb?provider=mayi", "http://localhost:54321/cb?provider=mayi"}},
		{"ipv6", "http://[::1]/cb", "http://[::1]:54321/cb", []string{"http://127.0.0.1:54321/cb", "http://[::1]:54321/other"}},
		{"private", "com.example.desktop:/cb", "com.example.desktop:/cb", []string{"com.example.other:/cb", "com.example.desktop:/other"}},
		{"claimed-https", "https://app.example/native/cb", "https://app.example/native/cb", []string{"https://app.example:8443/native/cb", "https://app.example/native/other"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			l := newLiveProtocol(t)
			ctx := context.Background()
			scope := l.proof.TenantIssuer
			management, err := administration.New(l.e.store, profileKeys{t}, clock{})
			if err != nil {
				t.Fatal(err)
			}
			actor := administration.Actor{ID: "admin", Scope: scope, Permissions: []string{"clients:write", "clients:read"}}
			client := clients.Client{ID: "desktop", Name: "Desktop", ApplicationType: "native", AuthMethod: "none", RedirectURIs: []string{test.registered}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}, AccessTokenSeconds: 300, Enabled: true}
			foreign := grants.Scope{TenantID: "b", Issuer: "https://auth.example/t/b"}
			if err := management.CreateClient(ctx, actor, foreign, client); !errors.Is(err, administration.ErrDenied) {
				t.Fatal("foreign registration", err)
			}
			if err := management.CreateClient(ctx, actor, scope, client); err != nil {
				t.Fatal("native registration", err)
			}
			stored, err := management.Client(ctx, actor, scope, client.ID)
			if err != nil || stored.ApplicationType != "native" || stored.RedirectURIs[0] != test.registered || !stored.AllowsRedirect(test.requested) {
				t.Fatal("native policy not persisted", err)
			}
			form := url.Values{"client_id": {"desktop"}, "response_type": {"code"}, "redirect_uri": {test.requested}, "resource": {"https://api.example"}, "scope": {"read offline_access"}, "state": {"native-state-at-least-16"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}, "authorization_details": {`[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"workflow:123","actions":["read"]}]`}}
			for _, callback := range test.forbidden {
				form.Set("redirect_uri", callback)
				w := protocolPost(l.protocol.Push, form, "", "")
				if w.Code != 400 || w.Header().Get("Location") != "" {
					t.Fatal("unregistered callback accepted", callback, w.Code)
				}
			}
			form.Set("redirect_uri", test.requested)
			w := protocolPost(l.protocol.Push, form, "", "")
			var pushed struct {
				URI string `json:"request_uri"`
			}
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &pushed) != nil {
				t.Fatal("native PAR", w.Code)
			}
			begun, err := l.consent.BeginPushed(ctx, authorization.PushedProof{TenantIssuer: scope, ClientID: "desktop", ReferenceHash: secretHash(strings.TrimPrefix(pushed.URI, "urn:ietf:params:oauth:request_uri:")), BrowserBindingHash: l.proof.BrowserBindingHash})
			if err != nil {
				t.Fatal(err)
			}
			proof := l.proof
			proof.AuthorizationHash = secretHash(begun.Handle)
			proof.CSRFHash = secretHash(begun.CSRFToken)
			view, err := l.consent.PrepareConsent(ctx, proof)
			if err != nil || view.RedirectURI != test.requested {
				t.Fatal("consent changed callback", err)
			}
			approved, err := l.consent.Decide(ctx, authorization.Decision{Proof: proof, Approve: true})
			if err != nil || approved.RedirectURI != test.requested {
				t.Fatal("approval changed callback", err)
			}
			redemption := url.Values{"client_id": {"desktop"}, "grant_type": {"authorization_code"}, "code": {approved.Code}, "code_verifier": {verifier}, "redirect_uri": {test.requested}, "resource": {"https://api.example"}}
			wrong := test.forbidden[0]
			if test.registered != test.requested {
				wrong = test.registered
			} // A second loopback port is forbidden at redemption.
			redemption.Set("redirect_uri", wrong)
			w = protocolPost(l.protocol.Token, redemption, "", "")
			if w.Code != 400 || strings.Contains(w.Body.String(), `"access_token"`) {
				t.Fatal("code destination substituted", w.Code)
			}
			redemption.Set("redirect_uri", test.requested)
			redemption.Set("code_verifier", strings.Repeat("z", 43))
			w = protocolPost(l.protocol.Token, redemption, "", "")
			if w.Code != 400 {
				t.Fatal("native client bypassed S256")
			}
			redemption.Set("code_verifier", verifier)
			w = protocolPost(l.protocol.Token, redemption, "", "")
			var issued protocolTokens
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Access == "" || issued.Refresh == "" {
				t.Fatal("native redemption", w.Code)
			}
			w = protocolPost(l.protocol.Token, redemption, "", "")
			if w.Code != 400 {
				t.Fatal("native code replay accepted")
			}
		})
	}
}
