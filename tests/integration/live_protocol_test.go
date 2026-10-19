package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	bffapi "github.com/startificial/mayi/examples/bff/adapters/api"
	bffcrypto "github.com/startificial/mayi/examples/bff/adapters/crypto"
	bffhttp "github.com/startificial/mayi/examples/bff/adapters/http"
	"github.com/startificial/mayi/examples/bff/adapters/memory"
	bffoauth "github.com/startificial/mayi/examples/bff/adapters/oauth"
	bff "github.com/startificial/mayi/examples/bff/services"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/adapters/outbound/egress"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/app"
	"github.com/startificial/mayi/internal/services/authentication"
	"github.com/startificial/mayi/internal/services/authorization"
	clientservice "github.com/startificial/mayi/internal/services/clients"
	grantservice "github.com/startificial/mayi/internal/services/grants"
	"github.com/startificial/mayi/internal/services/tokens"
	sdk "github.com/startificial/mayi/pkg/resource"
)

type liveProtocol struct {
	e              *foundation
	protocol       *oauth.Protocol
	consent        *authorization.Service
	proof          authorization.AccessProof
	clients        *clientservice.Service
	resourceSecret string
}

// This transport retains configured public URLs and HTTP codec behavior while
// routing the example in-process. Persistence, introspection and signing remain
// real PostgreSQL/HTTP/OpenBao; no alternate OAuth implementation is involved.
type applicationTransport struct{ as, api http.Handler }

func (t applicationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var handler http.Handler
	switch r.URL.Host {
	case "auth.example":
		handler = t.as
	case "api.example":
		handler = t.api
	default:
		return nil, errors.New("destination denied")
	}
	if r.RemoteAddr == "" {
		r = r.Clone(r.Context())
		r.RemoteAddr = "192.0.2.1:42000"
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	result := recorder.Result()
	result.Request = r
	return result, nil
}
func TestP2ReferenceBFFCompletesPARLoginAndProtectsResources(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	upstream := newOIDCFixture(t)
	if _, err := l.e.admin.Exec(ctx, `UPDATE mayi.clients SET redirect_uris=ARRAY['https://app.example/callback'],auth_method='client_secret_basic' WHERE tenant_id='a' AND client_id='web';
 INSERT INTO mayi_resource.permissions SELECT tenant_id,issuer,resource,subject,object_type,'123',actions FROM mayi_resource.permissions;
 INSERT INTO mayi_resource.labels(tenant_id,issuer,resource,object_type,identifier,name) SELECT tenant_id,issuer,resource,object_type,'123',name FROM mayi_resource.labels;
 INSERT INTO mayi_resource.permissions VALUES('a','https://auth.example/t/a','https://api.example','user:alice','https://api.example/types/fixture/v1','124',ARRAY['read']);`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.e.admin.Exec(ctx, `INSERT INTO mayi.external_identities VALUES('a','upstream',$1,'upstream-alice','user:alice')`, upstream.server.URL); err != nil {
		t.Fatal(err)
	}
	secret, err := l.clients.Rotate(ctx, clientservice.Operator{Scope: l.proof.TenantIssuer, ID: "operator", Permissions: []string{"clients:write"}}, "web", 0)
	if err != nil {
		t.Fatal(err)
	}
	l.e.config.PublicOrigin = "https://auth.example"
	l.e.config.AllowInsecureLoopback = true
	configureBrowserKeys(l.e)
	l.e.config.Tenants[0].IdentityProvider = &app.IdentityProviderConfig{ID: "upstream", Issuer: upstream.server.URL, ClientID: "mayi", ClientSecretEnv: "MAYI_A_IDP_SECRET", AuthorizationEndpoint: upstream.server.URL + "/authorize", TokenEndpoint: upstream.server.URL + "/token", JWKSURI: upstream.server.URL + "/jwks", SigningAlgorithm: "ES256"}
	l.e.secret["MAYI_A_IDP_SECRET"] = "fixture-secret"
	authorizationBrowser, err := app.NewBrowser(ctx, l.e.config, l.e.config.Tenants[0], l.e.store, func(name string) string { return l.e.secret[name] })
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /t/a/token", l.protocol.Token)
	mux.HandleFunc("GET /t/a/jwks", func(w http.ResponseWriter, r *http.Request) {
		var id, x, y string
		if err := l.e.admin.QueryRow(r.Context(), `SELECT key_id,x,y FROM mayi.signing_keys WHERE tenant_id='a' AND version=1`).Scan(&id, &x, &y); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": id, "x": x, "y": y}}})
	})
	mux.Handle("/t/a/", authorizationBrowser)
	introspection := httptest.NewServer(http.HandlerFunc(l.protocol.Introspect))
	defer introspection.Close()
	validator, err := sdk.New(sdk.Config{Tenant: "a", Issuer: l.proof.TenantIssuer.Issuer, Audience: "https://api.example", IntrospectionEndpoint: introspection.URL, ClientID: "resource-server", ClientSecret: l.resourceSecret, AllowInsecureLoopback: true, Profiles: []sdk.Profile{{Type: "https://api.example/types/fixture/v1", Actions: []sdk.Action{{Name: "read", Description: "Read items"}, {Name: "write", Description: "Write items"}}}}}, &currentPermission{e: l.e})
	if err != nil {
		t.Fatal(err)
	}
	loads := 0
	api := http.NewServeMux()
	api.HandleFunc("GET /documents/{id}", func(w http.ResponseWriter, r *http.Request) {
		raw, err := sdk.HeaderToken(r)
		if err == nil {
			err = validator.WithAccess(r.Context(), raw, sdk.Request{Type: "https://api.example/types/fixture/v1", Identifier: r.PathValue("id"), Action: "read", Permission: "read"}, func(context.Context, sdk.Principal) error { loads++; return nil })
		}
		if err != nil {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"123","body":"protected"}`)
	})
	wire := &http.Client{Transport: applicationTransport{as: mux, api: api}, Timeout: 5 * time.Second}
	client, err := bffoauth.New(l.proof.TenantIssuer.Issuer, "web", secret, "https://app.example/callback", "https://api.example", wire)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := bffcrypto.New([]bffcrypto.Key{{ID: "k1", Bytes: []byte(strings.Repeat("e", 32)), Active: true}})
	if err != nil {
		t.Fatal(err)
	}
	apiClient, err := bffapi.New("https://api.example", wire)
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	sessions, err := bff.New(store, cipher, client, apiClient, clock{}, bff.CredentialContext{Tenant: "a", Issuer: l.proof.TenantIssuer.Issuer, Client: "web", Resource: "https://api.example"})
	if err != nil {
		t.Fatal(err)
	}
	login, err := bff.NewLogin(sessions, store, cipher, client, bffcrypto.NewLoginSource(), clock{}, bff.AuthorizationRequest{Type: "https://api.example/types/fixture/v1", Identifier: "123", Permission: "read", Actions: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := bffhttp.New(sessions, login, "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	application := &browser{handler: handler.Routes(), cookies: map[string]*http.Cookie{}}
	mayi := &browser{handler: mux, cookies: map[string]*http.Cookie{}}
	started := application.request("GET", "https://app.example/login", "", "")
	if started.Code != 303 {
		t.Fatal("BFF PAR start", started.Code)
	}
	redirected := mayi.request("GET", started.Header().Get("Location"), "", "")
	if redirected.Code != 303 {
		t.Fatal("Mayi browser", redirected.Code, redirected.Body.String())
	}
	upstreamClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := upstreamClient.Get(redirected.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if w := mayi.request("GET", response.Header.Get("Location"), "", ""); w.Code != 303 {
		t.Fatal("upstream callback", w.Code, w.Body.String())
	}
	if w := mayi.request("GET", "https://auth.example/t/a/consent", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "while you are away") {
		t.Fatal("offline consent not visible", w.Code, w.Body.String())
	}
	data, err := base64.RawURLEncoding.DecodeString(mayi.cookies["__Host-mayi-flow-a"].Value)
	if err != nil {
		t.Fatal(err)
	}
	var flow struct{ CSRF string }
	if json.Unmarshal(data, &flow) != nil {
		t.Fatal("flow")
	}
	approved := mayi.request("POST", "https://auth.example/t/a/consent", url.Values{"csrf": {flow.CSRF}, "decision": {"approve"}}.Encode(), "https://auth.example")
	if approved.Code != 303 {
		t.Fatal("approval", approved.Code, approved.Body.String())
	}
	replayBrowser := application.clone()
	callback := application.request("GET", approved.Header().Get("Location"), "", "")
	if callback.Code != 303 {
		t.Fatal("BFF exchange/identity validation", callback.Code, callback.Body.String())
	}
	if replay := replayBrowser.request("GET", approved.Header().Get("Location"), "", ""); replay.Code != 400 {
		t.Fatal("BFF callback replay accepted")
	}
	for _, c := range application.cookies {
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
			t.Fatal("unsafe application cookie")
		}
	}
	if w := application.request("GET", "https://app.example/documents/123", "", ""); w.Code != 200 || loads != 1 {
		t.Fatal("BFF allowed document", w.Code, w.Body.String())
	}
	if w := application.request("GET", "https://app.example/documents/124", "", ""); w.Code != 403 || loads != 1 {
		t.Fatal("BFF object ceiling bypass", w.Code)
	}
	if w := application.request("GET", "https://app.example/documents/123?url=https://evil.example", "", ""); w.Code != 400 || loads != 1 {
		t.Fatal("arbitrary forwarding allowed")
	}
	if _, err = l.e.admin.Exec(ctx, `UPDATE mayi_resource.permissions SET actions=ARRAY['write'] WHERE identifier='123'`); err != nil {
		t.Fatal(err)
	}
	if w := application.request("GET", "https://app.example/documents/123", "", ""); w.Code != 403 || loads != 1 {
		t.Fatal("ACL removal did not cut off BFF")
	}
	if w := application.request("POST", "https://app.example/logout", "", "https://evil.example"); w.Code != 400 {
		t.Fatal("logout CSRF")
	}
	if w := application.request("POST", "https://app.example/logout", "", "https://app.example"); w.Code != 204 {
		t.Fatal("BFF logout", w.Code)
	}
	if w := application.request("GET", "https://app.example/documents/123", "", ""); w.Code != 401 {
		t.Fatal("ended BFF cookie accepted")
	}
}

func TestP2ClientAuthenticationRotationAssertionsAndMachinePolicy(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	actor := clientservice.Operator{Scope: l.proof.TenantIssuer, ID: "operator", Permissions: []string{"clients:write"}}
	next, err := l.clients.Rotate(ctx, actor, "resource-server", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{l.resourceSecret, next} {
		if _, err = l.clients.Authenticate(ctx, clientservice.Proof{ClientID: "resource-server", Method: "client_secret_basic", Secret: secret}); err != nil {
			t.Fatal("bounded overlap rejected", err)
		}
	}
	if _, err = l.clients.Authenticate(ctx, clientservice.Proof{ClientID: "resource-server", Method: "none"}); err == nil {
		t.Fatal("confidential auth downgraded")
	}
	if _, err = l.clients.Rotate(ctx, clientservice.Operator{Scope: l.proof.TenantIssuer, ID: "operator"}, "resource-server", time.Minute); !errors.Is(err, clientservice.ErrDenied) {
		t.Fatal("rotation authorization bypass")
	}
	if _, err = l.e.admin.Exec(ctx, `UPDATE mayi.client_secrets SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id='a' AND client_id='resource-server' AND secret_hash NOT IN(SELECT secret_hash FROM mayi.client_secrets WHERE tenant_id='a' AND client_id='resource-server' ORDER BY created_at DESC LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err = l.clients.Authenticate(ctx, clientservice.Proof{ClientID: "resource-server", Method: "client_secret_basic", Secret: l.resourceSecret}); err == nil {
		t.Fatal("expired overlap accepted")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "client-key", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.e.admin.Exec(ctx, `INSERT INTO mayi.clients(tenant_id,client_id,name,redirect_uris,access_token_seconds,auth_method,machine) VALUES('a','client:worker','Worker',ARRAY[]::text[],300,'private_key_jwt',true);
 INSERT INTO mayi.client_resources VALUES('a','client:worker','api');
 INSERT INTO mayi.client_object_types VALUES('a','client:worker','api','https://api.example/types/fixture/v1');
 INSERT INTO mayi.machine_authorizations VALUES('a','client:worker','https://api.example',ARRAY['read'],'{"version":1,"semantics":"object-actions-v1","resource":"https://api.example","details":[{"type":"https://api.example/types/fixture/v1","identifier":"workflow:123","actions":["read"]}]}');`); err != nil {
		t.Fatal(err)
	}
	if err = l.clients.ConfigureKeys(ctx, actor, "client:worker", string(inline), ""); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "client-key").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	assertion := func(id, audience string) string {
		now := time.Now()
		raw, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: "client:worker", Subject: "client:worker", Audience: jwt.Audience{audience}, ID: id, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(45 * time.Second))}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	audience := l.proof.TenantIssuer.Issuer + "/token"
	proof := clientservice.Proof{ClientID: "client:worker", Method: "private_key_jwt", Audience: audience, Assertion: assertion("one-use", audience)}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if _, err := l.clients.Authenticate(ctx, proof); err == nil {
				winners.Add(1)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("assertion replay race", winners.Load())
	}
	proof.Assertion = assertion("wrong-audience", "https://other.example/token")
	if _, err = l.clients.Authenticate(ctx, proof); err == nil {
		t.Fatal("assertion audience ignored")
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(inline)
	}))
	defer remote.Close()
	// This explicit loopback-only fixture bypasses HTTPS registry admission solely
	// to exercise the real constrained remote fetch without a public test domain.
	if _, err = l.e.admin.Exec(ctx, `UPDATE mayi.clients SET jwks=NULL,jwks_uri=$1,auth_version=auth_version+1 WHERE tenant_id='a' AND client_id='client:worker'`, remote.URL); err != nil {
		t.Fatal(err)
	}
	proof.Assertion = assertion("remote-key", audience)
	if _, err = l.clients.Authenticate(ctx, proof); err != nil {
		t.Fatal("registered remote key", err)
	}
	tokenRequest := url.Values{"client_id": {"client:worker"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion("machine-issue", audience)}, "grant_type": {"client_credentials"}, "resource": {"https://api.example"}, "scope": {"read"}}
	w := protocolPost(l.protocol.Token, tokenRequest, "", "")
	var issued protocolTokens
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Access == "" || issued.Refresh != "" || issued.Identity != "" {
		t.Fatal("machine issuance", w.Code, w.Body.String())
	}
	check := func(raw string) *httptest.ResponseRecorder {
		return protocolPost(l.protocol.Introspect, url.Values{"token": {raw}, "resource": {"https://api.example"}}, "resource-server", next)
	}
	result := check(issued.Access)
	var active struct {
		Active    bool   `json:"active"`
		Subject   string `json:"sub"`
		Client    string `json:"client_id"`
		Principal string `json:"principal_type"`
	}
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &active) != nil || !active.Active || active.Subject != "client:worker" || active.Subject != active.Client || active.Principal != "machine" {
		t.Fatal("machine identity", result.Code, result.Body.String())
	}
	if _, err = l.e.admin.Exec(ctx, `DELETE FROM mayi.machine_authorizations WHERE tenant_id='a'`); err != nil {
		t.Fatal(err)
	}
	result = check(issued.Access)
	if result.Code != 200 || strings.TrimSpace(result.Body.String()) != `{"active":false}` {
		t.Fatal("machine policy revocation ignored", result.Code, result.Body.String())
	}
}

func TestP2UserAndAdministratorControlsAuthenticateBeforeLoading(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	issued := l.redeem(t, l.code(t, true))
	service, err := grantservice.New(l.e.store, clock{}, l.proof.TenantIssuer)
	if err != nil {
		t.Fatal(err)
	}
	proof := grantservice.BrowserProof{Scope: l.proof.TenantIssuer, SessionHash: l.proof.SessionHash, BrowserHash: l.proof.BrowserBindingHash}
	records, err := service.List(ctx, proof)
	if err != nil || len(records) != 1 || records[0].Objects.IsZero() {
		t.Fatal("connected apps", err)
	}
	for _, mode := range []string{"browser", "tenant", "session"} {
		p := proof
		switch mode {
		case "browser":
			p.BrowserHash = secretHash("foreign")
		case "tenant":
			p.Scope.TenantID = "b"
			p.Scope.Issuer = "https://auth.example/t/b"
		case "session":
			p.SessionHash = secretHash("session-b")
		}
		if list, err := service.List(ctx, p); list != nil || !errors.Is(err, grantservice.ErrDenied) {
			t.Fatal("foreign grant details exposed", mode, err)
		}
	}
	if err = service.Revoke(ctx, proof, "unknown"); err != nil {
		t.Fatal("unknown revocation disclosed existence", err)
	}
	if err = service.AdminRevoke(ctx, grantservice.Operator{Scope: l.proof.TenantIssuer, ID: "operator"}, "user", "user:alice"); !errors.Is(err, grantservice.ErrDenied) {
		t.Fatal("admin permission missing")
	}
	if err = service.Revoke(ctx, proof, records[0].ID); err != nil {
		t.Fatal(err)
	}
	w := protocolPost(l.protocol.Introspect, url.Values{"token": {issued.Access}, "resource": {"https://api.example"}}, "resource-server", l.resourceSecret)
	if strings.TrimSpace(w.Body.String()) != `{"active":false}` {
		t.Fatal("user revocation not immediate", w.Body.String())
	}
	again := l.redeem(t, l.code(t, true))
	if err = service.AdminRevoke(ctx, grantservice.Operator{Scope: l.proof.TenantIssuer, ID: "operator", Permissions: []string{"grants:write"}}, "client", "web"); err != nil {
		t.Fatal(err)
	}
	w = protocolPost(l.protocol.Introspect, url.Values{"token": {again.Access}, "resource": {"https://api.example"}}, "resource-server", l.resourceSecret)
	if strings.TrimSpace(w.Body.String()) != `{"active":false}` {
		t.Fatal("incident revocation not immediate")
	}
	sessions, err := authentication.NewSessions(l.e.store, clock{}, l.proof.TenantIssuer)
	if err != nil {
		t.Fatal(err)
	}
	sessionProof := authentication.SessionProof{Scope: l.proof.TenantIssuer, SessionHash: l.proof.SessionHash, BrowserHash: l.proof.BrowserBindingHash}
	list, err := sessions.List(ctx, sessionProof)
	if err != nil || len(list) != 1 || !list[0].Current {
		t.Fatal("session list", err)
	}
	foreign := sessionProof
	foreign.BrowserHash = secretHash("wrong")
	if list, err := sessions.List(ctx, foreign); list != nil || !errors.Is(err, authentication.ErrDenied) {
		t.Fatal("foreign session list", err)
	}
	if err = sessions.Touch(ctx, sessionProof); err != nil {
		t.Fatal(err)
	}
	if _, err = l.e.admin.Exec(ctx, `UPDATE mayi.browser_sessions SET last_used_at=clock_timestamp()-interval '16 minutes' WHERE tenant_id='a'`); err != nil {
		t.Fatal(err)
	}
	if list, err := sessions.List(ctx, sessionProof); list != nil || !errors.Is(err, authentication.ErrDenied) {
		t.Fatal("idle session accepted", err)
	}
}

func newLiveProtocol(t *testing.T) *liveProtocol {
	t.Helper()
	ctx := context.Background()
	signer := setup(t).signer
	e, _, _, proof := setupAuthorization(t)
	e.config.Tenants = []app.TenantConfig{{ID: "a"}}
	installBrowserResourceAuthority(t, e)
	owner, err := postgres.NewResourceConsent(e.store, []postgres.ResourceConsentConfig{{Scope: proof.TenantIssuer, Resource: "https://api.example"}})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := cryptoadapter.NewSecretHasher([]cryptoadapter.HashKey{{Version: 1, Key: []byte(strings.Repeat("k", 32)), Active: true}})
	if err != nil {
		t.Fatal(err)
	}
	source, err := cryptoadapter.NewKeyedAuthorizationSource(proof.TenantIssuer, hash)
	if err != nil {
		t.Fatal(err)
	}
	consent, err := authorization.New(e.store, clock{}, source, owner)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := cryptoadapter.NewClientSecrets(proof.TenantIssuer, hash)
	if err != nil {
		t.Fatal(err)
	}
	assertions, err := cryptoadapter.NewClientAssertions(egress.NewRegisteredKeys(true))
	if err != nil {
		t.Fatal(err)
	}
	admission, err := authentication.NewAdmission(e.store, authentication.DefaultBudgetRules())
	if err != nil {
		t.Fatal(err)
	}
	clients, err := clientservice.New(e.store, clock{}, assertions, secrets, proof.TenantIssuer, admission)
	if err != nil {
		t.Fatal(err)
	}
	material, err := cryptoadapter.NewKeyedMaterialSource(proof.TenantIssuer, hash, tokens.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := app.NewIssuance(e.store, clock{}, signer, material, e.store, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	machine, err := tokens.NewMachine(e.store, clock{}, material, signer, admission)
	if err != nil {
		t.Fatal(err)
	}

	proofs, err := tokens.NewProofs(cryptoadapter.NewDPoP(), e.store, clock{})
	if err != nil {
		t.Fatal(err)
	}
	status, err := tokens.NewStatus(e.store, hash, material, proofs, admission)
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := oauth.NewProtocol(proof.TenantIssuer, clients, consent, issuance, machine, status, hash, proofs)
	if err != nil {
		t.Fatal(err)
	}
	data, err := signer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(data, &keys) != nil {
		t.Fatal("JWKS")
	}
	public, err := json.Marshal(keys.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	var point struct {
		ID string `json:"kid"`
		X  string `json:"x"`
		Y  string `json:"y"`
	}
	if json.Unmarshal(public, &point) != nil {
		t.Fatal("point")
	}
	if _, err = e.admin.Exec(ctx, `INSERT INTO mayi.signing_keys VALUES('a',1,$1,$2,$3,clock_timestamp(),true)`, point.ID, point.X, point.Y); err != nil {
		t.Fatal(err)
	}
	if _, err = e.admin.Exec(ctx, `INSERT INTO mayi.clients(tenant_id,client_id,name,redirect_uris,access_token_seconds,auth_method,introspection) VALUES('a','resource-server','Resource server',ARRAY['https://api.example/cb'],300,'client_secret_basic',true);
 INSERT INTO mayi.client_resources VALUES('a','resource-server','api');
 INSERT INTO mayi.client_object_types VALUES('a','resource-server','api','https://api.example/types/fixture/v1');`); err != nil {
		t.Fatal(err)
	}
	secret, err := clients.Rotate(ctx, clientservice.Operator{Scope: proof.TenantIssuer, ID: "operator", Permissions: []string{"clients:write"}}, "resource-server", 0)
	if err != nil {
		t.Fatal(err)
	}
	return &liveProtocol{e, protocol, consent, proof, clients, secret}
}
func protocolPost(handler http.HandlerFunc, form url.Values, id, secret string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://auth.example/t/a/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		r.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}
func (l *liveProtocol) code(t *testing.T, offline bool) string {
	return l.objectCode(t, "workflow:123", offline)
}
func (l *liveProtocol) objectCode(t *testing.T, identifier string, offline bool) string {
	t.Helper()
	scope := "read openid"
	if offline {
		scope += " offline_access"
	}
	form := url.Values{"client_id": {"web"}, "response_type": {"code"}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "resource": {"https://api.example"}, "scope": {scope}, "nonce": {"nonce-for-relying-client"}, "state": {"downstream-state-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}, "authorization_details": {`[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"workflow:123","actions":["read"]}]`}}
	form.Set("authorization_details", strings.ReplaceAll(form.Get("authorization_details"), "workflow:123", identifier))
	w := protocolPost(l.protocol.Push, form, "", "")
	var pushed struct {
		URI string `json:"request_uri"`
	}
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &pushed) != nil || pushed.URI == "" {
		t.Fatal("public PAR", w.Code, w.Body.String())
	}
	begun, err := l.consent.BeginPushed(context.Background(), authorization.PushedProof{TenantIssuer: l.proof.TenantIssuer, ClientID: "web", ReferenceHash: secretHash(strings.TrimPrefix(pushed.URI, "urn:ietf:params:oauth:request_uri:")), BrowserBindingHash: l.proof.BrowserBindingHash})
	if err != nil {
		t.Fatal("begin PAR", err)
	}
	proof := l.proof
	proof.AuthorizationHash = secretHash(begun.Handle)
	proof.CSRFHash = secretHash(begun.CSRFToken)
	if _, err = l.consent.PrepareConsent(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	approved, err := l.consent.Decide(context.Background(), authorization.Decision{Proof: proof, Approve: true})
	if err != nil {
		t.Fatal(err)
	}
	return approved.Code
}

type protocolTokens struct {
	Access   string `json:"access_token"`
	Refresh  string `json:"refresh_token"`
	Identity string `json:"id_token"`
}

func (l *liveProtocol) redeem(t *testing.T, code string) protocolTokens {
	t.Helper()
	w := protocolPost(l.protocol.Token, url.Values{"client_id": {"web"}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "resource": {"https://api.example"}}, "", "")
	var result protocolTokens
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Access == "" {
		t.Fatal("public token", w.Code, w.Body.String())
	}
	return result
}

type currentPermission struct {
	e     *foundation
	calls atomic.Int32
}

func (g *currentPermission) WithPermission(ctx context.Context, p sdk.Principal, r sdk.Request, fn func(context.Context) error) error {
	tx, err := g.e.admin.Begin(ctx)
	if err != nil {
		return sdk.ErrUnavailable
	}
	defer tx.Rollback(ctx)
	var version uint64
	if err = tx.QueryRow(ctx, `SELECT version FROM mayi_resource.authorities WHERE tenant_id=$1 AND issuer=$2 AND resource='https://api.example' AND subject=$3 AND enabled FOR SHARE`, p.Tenant, p.Issuer, p.Subject).Scan(&version); err != nil {
		return sdk.ErrDenied
	}
	var allowed bool
	if err = tx.QueryRow(ctx, `SELECT $6=ANY(actions) FROM mayi_resource.permissions WHERE tenant_id=$1 AND issuer=$2 AND resource='https://api.example' AND subject=$3 AND object_type=$4 AND identifier=$5 FOR SHARE`, p.Tenant, p.Issuer, p.Subject, r.Type, r.Identifier, r.Action).Scan(&allowed); err != nil || !allowed {
		return sdk.ErrDenied
	}
	g.calls.Add(1)
	if err = fn(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func TestP2PublicProtocolAndSDKEnforceObjectAuthorityAndImmediateCutoff(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	credential := l.redeem(t, l.code(t, true))
	if credential.Refresh == "" || credential.Identity == "" {
		t.Fatal("approved offline/OIDC options lost")
	}
	parsed, err := jwt.ParseSigned(credential.Identity, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var identity struct {
		Audience string `json:"aud"`
		Nonce    string `json:"nonce"`
		Auth     int64  `json:"auth_time"`
	}
	if parsed.UnsafeClaimsWithoutVerification(&identity) != nil || identity.Audience != "web" || identity.Nonce != "nonce-for-relying-client" || identity.Auth == 0 {
		t.Fatal("wrong downstream identity claims")
	}
	introspection := httptest.NewServer(http.HandlerFunc(l.protocol.Introspect))
	defer introspection.Close()
	guard := &currentPermission{e: l.e}
	client, err := sdk.New(sdk.Config{Tenant: "a", Issuer: l.proof.TenantIssuer.Issuer, Audience: "https://api.example", IntrospectionEndpoint: introspection.URL, ClientID: "resource-server", ClientSecret: l.resourceSecret, AllowInsecureLoopback: true, Profiles: []sdk.Profile{{Type: "https://api.example/types/fixture/v1", Actions: []sdk.Action{{Name: "read", Description: "Read items"}, {Name: "write", Description: "Write items"}}}}}, guard)
	if err != nil {
		t.Fatal(err)
	}
	payloads := 0
	access := func(token, id, action string) error {
		return client.WithAccess(ctx, token, sdk.Request{Type: "https://api.example/types/fixture/v1", Identifier: id, Action: action, Permission: "read"}, func(context.Context, sdk.Principal) error { payloads++; return nil })
	}
	if err = access(credential.Access, "workflow:123", "read"); err != nil || payloads != 1 {
		t.Fatal("approved object denied", err)
	}
	for _, test := range []struct{ token, id, action string }{{credential.Access, "workflow:124", "read"}, {credential.Access, "workflow:123", "write"}, {credential.Identity, "workflow:123", "read"}, {"unknown", "workflow:123", "read"}} {
		if err = access(test.token, test.id, test.action); !errors.Is(err, sdk.ErrDenied) {
			t.Fatal("denied request passed", err)
		}
	}
	if payloads != 1 || guard.calls.Load() != 1 {
		t.Fatal("denied request loaded protected content or ACL")
	}
	if _, err = l.e.admin.Exec(ctx, `UPDATE mayi_resource.permissions SET actions=ARRAY['write']`); err != nil {
		t.Fatal(err)
	}
	if err = access(credential.Access, "workflow:123", "read"); !errors.Is(err, sdk.ErrDenied) || payloads != 1 {
		t.Fatal("current permission loss ignored", err)
	}
	if _, err = l.e.admin.Exec(ctx, `UPDATE mayi_resource.permissions SET actions=ARRAY['read','write']`); err != nil {
		t.Fatal(err)
	}
	refreshForm := url.Values{"client_id": {"web"}, "grant_type": {"refresh_token"}, "refresh_token": {credential.Refresh}, "resource": {"https://api.example"}}
	rotated := protocolPost(l.protocol.Token, refreshForm, "", "")
	var next protocolTokens
	if rotated.Code != 200 || json.Unmarshal(rotated.Body.Bytes(), &next) != nil || next.Refresh == "" || next.Refresh == credential.Refresh {
		t.Fatal("rotation", rotated.Code, rotated.Body.String())
	}
	if err = access(next.Access, "workflow:123", "read"); err != nil {
		t.Fatal("rotated authority", err)
	}
	replay := protocolPost(l.protocol.Token, refreshForm, "", "")
	if replay.Code != 400 {
		t.Fatal("refresh replay accepted")
	}
	if err = access(next.Access, "workflow:123", "read"); !errors.Is(err, sdk.ErrDenied) {
		t.Fatal("refresh replay did not immediately cut off grant", err)
	}
	// A revoked credential and an unknown credential have the same response.
	for _, raw := range []string{next.Access, "not-a-credential"} {
		w := protocolPost(l.protocol.Revoke, url.Values{"client_id": {"web"}, "token": {raw}}, "", "")
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("revocation disclosed state", w.Code)
		}
	}
	if _, err = l.e.admin.Exec(ctx, `UPDATE mayi.resources SET token_format='opaque' WHERE tenant_id='a'`); err != nil {
		t.Fatal(err)
	}
	opaque := l.redeem(t, l.code(t, false))
	if strings.Count(opaque.Access, ".") != 1 || opaque.Refresh != "" || opaque.Identity == "" {
		t.Fatal("opaque/online token profile")
	}
	if err = access(opaque.Access, "workflow:123", "read"); err != nil {
		t.Fatal("opaque access", err)
	}
}
