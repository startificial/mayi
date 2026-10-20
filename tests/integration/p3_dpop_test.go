package integration_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/authorization"
	clientservice "github.com/startificial/mayi/internal/services/clients"
	sdk "github.com/startificial/mayi/pkg/resource"
)

func proofKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func thumbprint(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: &key.PublicKey}
	b, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func dpopPost(handler http.HandlerFunc, form url.Values, jwt string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://auth.example/t/a/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if jwt != "" {
		r.Header.Set("DPoP", jwt)
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}
func requireProtocolError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if w.Code != status || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error != code || strings.Contains(w.Body.String(), `"access_token"`) {
		t.Fatal("unexpected safe protocol failure", w.Code, code)
	}
}
func requireNonce(t *testing.T, w *httptest.ResponseRecorder, status int) string {
	t.Helper()
	requireProtocolError(t, w, status, "use_dpop_nonce")
	n := w.Header().Get("DPoP-Nonce")
	if len(n) < 43 || len(n) > 128 {
		t.Fatal("missing bounded nonce")
	}
	return n
}

func boundAuthorizationCode(t *testing.T, l *liveProtocol, key *ecdsa.PrivateKey, client string) string {
	t.Helper()
	form := url.Values{"client_id": {client}, "response_type": {"code"}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "resource": {"https://api.example"}, "scope": {"read offline_access"}, "state": {"dpop-client-state-at-least-16"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}, "dpop_jkt": {thumbprint(t, key)}, "authorization_details": {`[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"workflow:123","actions":["read"]}]`}}
	missing := url.Values{}
	for k, v := range form {
		missing[k] = v
	}
	missing.Del("dpop_jkt")
	if w := protocolPost(l.protocol.Push, missing, "", ""); w.Code != 400 {
		t.Fatal("client binding policy bypassed at PAR", w.Code)
	}
	w := protocolPost(l.protocol.Push, form, "", "")
	var pushed struct {
		URI string `json:"request_uri"`
	}
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &pushed) != nil {
		t.Fatal("bound PAR failed", w.Code)
	}
	started, err := l.consent.BeginPushed(context.Background(), authorization.PushedProof{TenantIssuer: l.proof.TenantIssuer, ClientID: client, ReferenceHash: secretHash(strings.TrimPrefix(pushed.URI, "urn:ietf:params:oauth:request_uri:")), BrowserBindingHash: l.proof.BrowserBindingHash})
	if err != nil {
		t.Fatal(err)
	}
	p := l.proof
	p.AuthorizationHash = secretHash(started.Handle)
	p.CSRFHash = secretHash(started.CSRFToken)
	if _, err := l.consent.PrepareConsent(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	approved, err := l.consent.Decide(context.Background(), authorization.Decision{Proof: p, Approve: true})
	if err != nil {
		t.Fatal(err)
	}
	return approved.Code
}

func TestP3DPoPClientResourceNonceRotationReplayAndCutoff(t *testing.T) {
	for _, format := range []string{"jwt", "opaque"} {
		t.Run(format, func(t *testing.T) { testDPoPClientResource(t, format) })
	}
}
func testDPoPClientResource(t *testing.T, tokenFormat string) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	if _, err := l.e.admin.Exec(ctx, `UPDATE mayi.resources SET token_format=$1 WHERE tenant_id='a' AND resource_id='api'`, tokenFormat); err != nil {
		t.Fatal(err)
	}
	key, other := proofKey(t), proofKey(t)
	management, err := administration.New(l.e.store, profileKeys{t}, clock{})
	if err != nil {
		t.Fatal(err)
	}
	actor := administration.Actor{ID: "admin", Scope: l.proof.TenantIssuer, Permissions: []string{"clients:write", "clients:read"}}
	client := clients.Client{ID: "agent", Name: "Bound agent", AuthMethod: "none", RequireBinding: true, RedirectURIs: []string{"https://app.example/cb?provider=mayi"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}, AccessTokenSeconds: 300, Enabled: true}
	if err := management.CreateClient(ctx, actor, actor.Scope, client); err != nil {
		t.Fatal(err)
	}
	stored, err := management.Client(ctx, actor, actor.Scope, client.ID)
	if err != nil || !stored.RequireBinding {
		t.Fatal("client binding policy not persisted", err)
	}
	code := boundAuthorizationCode(t, l, key, "agent")
	var sequence atomic.Int64
	signed := func(k *ecdsa.PrivateKey, nonce, method, target, access string) string {
		claims := map[string]any{"nonce": nonce, "jti": fmt.Sprintf("p3-proof-%020d", sequence.Add(1)), "htm": method, "htu": target}
		if access != "" {
			sum := sha256.Sum256([]byte(access))
			claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
		}
		return proof(t, k, claims)
	}
	tokenForm := url.Values{"client_id": {"agent"}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "resource": {"https://api.example"}}
	tokenURL := l.proof.TenantIssuer.Issuer + "/token"
	nonceOther := requireNonce(t, dpopPost(l.protocol.Token, tokenForm, signed(other, "", "POST", tokenURL, "")), 400)
	requireProtocolError(t, dpopPost(l.protocol.Token, tokenForm, signed(other, nonceOther, "POST", tokenURL, "")), 400, "invalid_grant")
	tokenNonce := requireNonce(t, dpopPost(l.protocol.Token, tokenForm, signed(key, "", "POST", tokenURL, "")), 400)
	w := dpopPost(l.protocol.Token, tokenForm, signed(key, tokenNonce, "POST", tokenURL, ""))
	var issued struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Type    string `json:"token_type"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Access == "" || issued.Refresh == "" || issued.Type != "DPoP" {
		t.Fatal("bound issuance failed", w.Code)
	}
	introspection := httptest.NewServer(http.HandlerFunc(l.protocol.Introspect))
	defer introspection.Close()
	validator, err := sdk.New(sdk.Config{RequireDPoP: true, Tenant: "a", Issuer: l.proof.TenantIssuer.Issuer, Audience: "https://api.example", IntrospectionEndpoint: introspection.URL, ClientID: "resource-server", ClientSecret: l.resourceSecret, AllowInsecureLoopback: true, Profiles: []sdk.Profile{{Type: "https://api.example/types/fixture/v1", Actions: []sdk.Action{{Name: "read", Description: "Read"}}}}}, &currentPermission{e: l.e})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := sdk.NewMetadata(sdk.MetadataConfig{RequireDPoP: true, Issuer: l.proof.TenantIssuer.Issuer, Audience: "https://api.example", Name: "API", PermissionScopes: []string{"read"}, AuthorizationDetailTypes: []string{"https://api.example/types/fixture/v1"}})
	if err != nil {
		t.Fatal(err)
	}
	var loads atomic.Int32
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := sdk.HeaderToken(r)
		if err == nil {
			err = validator.WithAccess(r.Context(), raw, sdk.Request{Type: "https://api.example/types/fixture/v1", Identifier: "workflow:123", Action: "read", Permission: "read", Proof: r.Header.Get("DPoP"), Method: r.Method, URL: "https://api.example" + r.URL.RequestURI()}, func(context.Context, sdk.Principal) error { loads.Add(1); return nil })
		}
		if err != nil {
			metadata.WriteChallenge(w, err)
			return
		}
		w.WriteHeader(204)
	})
	resourceURL := "https://api.example/documents/workflow:123"
	access := func(scheme, jwt string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", resourceURL+"?view=summary", nil)
		r.Header.Set("Authorization", scheme+" "+issued.Access)
		if jwt != "" {
			r.Header.Set("DPoP", jwt)
		}
		r.Header.Set("X-Forwarded-Host", "evil.example")
		w := httptest.NewRecorder()
		api(w, r)
		return w
	}
	requireProtocolError(t, access("Bearer", ""), 401, "invalid_dpop_proof")
	requireProtocolError(t, access("DPoP", ""), 401, "invalid_dpop_proof")
	resourceNonce := requireNonce(t, access("DPoP", signed(key, "", "GET", resourceURL, issued.Access)), 401)
	if !strings.HasPrefix(access("DPoP", signed(other, resourceNonce, "GET", resourceURL, issued.Access)).Header().Get("WWW-Authenticate"), "DPoP ") {
		t.Fatal("wrong scheme challenge")
	}
	for _, mode := range []string{"wrong key", "wrong ath", "wrong method", "wrong target"} {
		k, n, m, u, raw := key, resourceNonce, "GET", resourceURL, issued.Access
		switch mode {
		case "wrong key":
			k = other
		case "wrong ath":
			raw = "copied-token"
		case "wrong method":
			m = "POST"
		case "wrong target":
			u = "https://api.example/other"
		}
		requireProtocolError(t, access("DPoP", signed(k, n, m, u, raw)), 401, "invalid_dpop_proof")
	}
	if loads.Load() != 0 {
		t.Fatal("denied proof loaded protected payload")
	}
	// A token nonce cannot stand in for a resource nonce, even for the same key.
	requireNonce(t, access("DPoP", signed(key, tokenNonce, "GET", resourceURL, issued.Access)), 401)
	valid := signed(key, resourceNonce, "GET", resourceURL, issued.Access)
	if w := access("DPoP", valid); w.Code != 204 || loads.Load() != 1 {
		t.Fatal("resource proof rejected", w.Code)
	}
	requireProtocolError(t, access("DPoP", valid), 401, "invalid_dpop_proof")
	if w := access("DPoP", signed(key, resourceNonce, "GET", resourceURL, issued.Access)); w.Code != 204 {
		t.Fatal("fresh jti cannot reuse current nonce", w.Code)
	}
	concurrent := signed(key, resourceNonce, "GET", resourceURL, issued.Access)
	results := make(chan int, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() { defer group.Done(); results <- access("DPoP", concurrent).Code }()
	}
	group.Wait()
	close(results)
	wins := 0
	for status := range results {
		if status == 204 {
			wins++
		} else if status != 401 {
			t.Fatal("unexpected replay failure", status)
		}
	}
	if wins != 1 || loads.Load() != 3 {
		t.Fatal("concurrent proof replay", wins, loads.Load())
	}
	if _, err := l.e.admin.Exec(ctx, `UPDATE mayi.proof_nonces SET expires_at=clock_timestamp()-interval '1 second' WHERE purpose='resource'`); err != nil {
		t.Fatal(err)
	}
	resourceNonce = requireNonce(t, access("DPoP", signed(key, resourceNonce, "GET", resourceURL, issued.Access)), 401)
	if loads.Load() != 3 {
		t.Fatal("expired nonce reached payload")
	}
	for _, table := range []string{"proof_nonces", "proof_replays"} {
		if _, err := l.e.admin.Exec(ctx, "ALTER TABLE mayi."+table+" RENAME TO unavailable_state"); err != nil {
			t.Fatal(err)
		}
		w := access("DPoP", signed(key, resourceNonce, "GET", resourceURL, issued.Access))
		requireProtocolError(t, w, 503, "temporarily_unavailable")
		if w.Header().Get("WWW-Authenticate") != "" || w.Header().Get("DPoP-Nonce") != "" || loads.Load() != 3 {
			t.Fatal("missing shared state invited retry or reached payload")
		}
		if _, err := l.e.admin.Exec(ctx, "ALTER TABLE mayi.unavailable_state RENAME TO "+table); err != nil {
			t.Fatal(err)
		}
	}
	refresh := url.Values{"client_id": {"agent"}, "grant_type": {"refresh_token"}, "refresh_token": {issued.Refresh}, "resource": {"https://api.example"}}
	requireProtocolError(t, dpopPost(l.protocol.Token, refresh, ""), 400, "invalid_grant")
	requireProtocolError(t, dpopPost(l.protocol.Token, refresh, signed(other, nonceOther, "POST", tokenURL, "")), 400, "invalid_grant")
	w = dpopPost(l.protocol.Token, refresh, signed(key, tokenNonce, "POST", tokenURL, ""))
	if w.Code != 200 {
		t.Fatal("bound refresh rotation failed", w.Code)
	}
	requireProtocolError(t, dpopPost(l.protocol.Token, refresh, signed(key, tokenNonce, "POST", tokenURL, "")), 400, "invalid_grant")
	requireProtocolError(t, access("DPoP", signed(key, resourceNonce, "GET", resourceURL, issued.Access)), 401, "invalid_token")
	if loads.Load() != 3 {
		t.Fatal("refresh replay did not cut off resource access")
	}
	var rawNonce bool
	if err := l.e.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.proof_nonces WHERE nonce_hash=$1)`, resourceNonce).Scan(&rawNonce); err != nil || rawNonce {
		t.Fatal("raw nonce persisted", err)
	}
}

func TestP3MachineClientBindingRequiresProof(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	key := proofKey(t)
	management, err := administration.New(l.e.store, profileKeys{t}, clock{})
	if err != nil {
		t.Fatal(err)
	}
	actor := administration.Actor{ID: "admin", Scope: l.proof.TenantIssuer, Permissions: []string{"clients:write"}}
	c := clients.Client{ID: "client:bound-worker", Name: "Bound worker", AuthMethod: "client_secret_basic", Machine: true, RequireBinding: true, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}, AccessTokenSeconds: 300, Enabled: true}
	if err := management.CreateClient(ctx, actor, actor.Scope, c); err != nil {
		t.Fatal(err)
	}
	secret, err := l.clients.Rotate(ctx, clientservice.Operator{ID: "admin", Scope: actor.Scope, Permissions: actor.Permissions}, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.e.admin.Exec(ctx, `INSERT INTO mayi.machine_authorizations VALUES('a','client:bound-worker','https://api.example',ARRAY['read'],'{"version":1,"semantics":"object-actions-v1","resource":"https://api.example","details":[{"type":"https://api.example/types/fixture/v1","identifier":"workflow:123","actions":["read"]}]}')`); err != nil {
		t.Fatal(err)
	}
	post := func(jwt string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", l.proof.TenantIssuer.Issuer+"/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "resource": {"https://api.example"}, "scope": {"read"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(url.QueryEscape(c.ID), url.QueryEscape(secret))
		if jwt != "" {
			r.Header.Set("DPoP", jwt)
		}
		w := httptest.NewRecorder()
		l.protocol.Token(w, r)
		return w
	}
	requireProtocolError(t, post(""), 400, "invalid_grant")
	nonce := requireNonce(t, post(proof(t, key, map[string]any{"nonce": "", "jti": "machine-initial-proof-123456"})), 400)
	w := post(proof(t, key, map[string]any{"nonce": nonce, "jti": "machine-bound-proof-123456"}))
	var issued struct {
		Access  string `json:"access_token"`
		Type    string `json:"token_type"`
		Refresh string `json:"refresh_token"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Type != "DPoP" || issued.Access == "" || issued.Refresh != "" {
		t.Fatal("machine binding failed", w.Code)
	}
	w = protocolPost(l.protocol.Introspect, url.Values{"token": {issued.Access}, "resource": {"https://api.example"}}, "resource-server", l.resourceSecret)
	var claims struct {
		Subject   string `json:"sub"`
		Principal string `json:"principal_type"`
		CNF       struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &claims) != nil || claims.Subject != c.ID || claims.Principal != "machine" || claims.CNF.JKT != thumbprint(t, key) {
		t.Fatal("machine identity or binding lost")
	}
}
