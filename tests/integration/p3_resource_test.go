package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	sdk "github.com/startificial/mayi/pkg/resource"
)

func TestP3ResourceChallengeDiscoveryAndOnlineCutoff(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	issued := l.redeem(t, l.code(t, true))
	introspection := httptest.NewServer(http.HandlerFunc(l.protocol.Introspect))
	defer introspection.Close()
	validator, err := sdk.New(sdk.Config{Tenant: "a", Issuer: l.proof.TenantIssuer.Issuer, Audience: "https://api.example", IntrospectionEndpoint: introspection.URL, ClientID: "resource-server", ClientSecret: l.resourceSecret, AllowInsecureLoopback: true, Profiles: []sdk.Profile{{Type: "https://api.example/types/fixture/v1", Actions: []sdk.Action{{Name: "read", Description: "Read items"}}}}}, &currentPermission{e: l.e})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := sdk.NewMetadata(sdk.MetadataConfig{Issuer: l.proof.TenantIssuer.Issuer, Audience: "https://api.example", Name: "Example API", PermissionScopes: []string{"read"}, AuthorizationDetailTypes: []string{"https://api.example/types/fixture/v1"}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(metadata.MetadataPath(), metadata)
	loads := 0
	mux.HandleFunc("GET /documents/{id}", func(w http.ResponseWriter, r *http.Request) {
		raw, err := sdk.HeaderToken(r)
		if err == nil {
			err = validator.WithAccess(r.Context(), raw, sdk.Request{Type: "https://api.example/types/fixture/v1", Identifier: r.PathValue("id"), Action: "read", Permission: "read"}, func(context.Context, sdk.Principal) error { loads++; return nil })
		}
		if err != nil {
			metadata.WriteChallenge(w, err)
			return
		}
		w.WriteHeader(204)
	})
	request := func(path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://api.example"+path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	w := request("/documents/workflow:123", "")
	if w.Code != 401 || strings.Contains(w.Header().Get("WWW-Authenticate"), "error=") || !strings.Contains(w.Header().Get("WWW-Authenticate"), metadata.MetadataURL()) || loads != 0 {
		t.Fatal("missing-credential discovery challenge", w.Code)
	}
	w = request(metadata.MetadataPath(), "")
	var doc struct {
		Resource string   `json:"resource"`
		Servers  []string `json:"authorization_servers"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &doc) != nil || doc.Resource != "https://api.example" || len(doc.Servers) != 1 || doc.Servers[0] != l.proof.TenantIssuer.Issuer {
		t.Fatal("resource discovery", w.Code, w.Body.String())
	}
	w = request("/documents/workflow:123", issued.Access)
	if w.Code != 204 || loads != 1 {
		t.Fatal("authorized resource", w.Code, w.Body.String())
	}
	for _, path := range []string{"/documents/workflow:124", "/documents/unknown"} {
		w = request(path, issued.Access)
		if w.Code != 401 || loads != 1 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatal("object denial disclosed existence or loaded payload", w.Code)
		}
	}
	if _, err = l.e.admin.Exec(ctx, `DELETE FROM mayi_resource.permissions WHERE tenant_id='a' AND identifier='workflow:123'`); err != nil {
		t.Fatal(err)
	}
	w = request("/documents/workflow:123", issued.Access)
	if w.Code != 401 || loads != 1 {
		t.Fatal("permission loss did not stop payload", w.Code)
	}
	w = protocolPost(l.protocol.Revoke, url.Values{"client_id": {"web"}, "token": {issued.Access}}, "", "")
	if w.Code != 200 {
		t.Fatal("revocation failed", w.Code)
	}
	w = request("/documents/workflow:123", issued.Access)
	if w.Code != 401 || loads != 1 {
		t.Fatal("revocation did not stop payload", w.Code)
	}
}
