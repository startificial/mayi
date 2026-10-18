package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/app"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type upstreamCode struct{ nonce, challenge string }
type oidcFixture struct {
	server            *httptest.Server
	key               *ecdsa.PrivateKey
	mu                sync.Mutex
	codes             map[string]upstreamCode
	issued, exchanges int
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &oidcFixture{key: key, codes: map[string]upstreamCode{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks", "response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{"ES256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "upstream-key", Use: "sig", Algorithm: "ES256"}}})
		case "/authorize":
			q := r.URL.Query()
			if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("client_id") != "mayi" || q.Get("redirect_uri") != "https://auth.example/t/a/upstream/callback" || q.Get("max_age") != "0" {
				http.Error(w, "invalid fixture request", 400)
				return
			}
			f.mu.Lock()
			f.issued++
			code := fmt.Sprintf("fixture-code-%d", f.issued)
			f.codes[code] = upstreamCode{q.Get("nonce"), q.Get("code_challenge")}
			f.mu.Unlock()
			cb, _ := url.Parse(q.Get("redirect_uri"))
			cb.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {f.server.URL}}.Encode()
			http.Redirect(w, r, cb.String(), 303)
		case "/token":
			if r.ParseForm() != nil {
				http.Error(w, "bad form", 400)
				return
			}
			id, secret, ok := r.BasicAuth()
			if !ok || id != "mayi" || secret != "fixture-secret" || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != "https://auth.example/t/a/upstream/callback" {
				http.Error(w, "bad authentication", 400)
				return
			}
			f.mu.Lock()
			f.exchanges++
			entry, found := f.codes[r.PostForm.Get("code")]
			delete(f.codes, r.PostForm.Get("code"))
			f.mu.Unlock()
			h := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if !found || base64.RawURLEncoding.EncodeToString(h[:]) != entry.challenge {
				http.Error(w, "bad verifier", 400)
				return
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "upstream-key").WithType("JWT"))
			if err != nil {
				http.Error(w, "fixture signer", 500)
				return
			}
			now := time.Now()
			token, err := jwt.Signed(signer).Claims(map[string]any{"iss": f.server.URL, "sub": "upstream-alice", "aud": "mayi", "nonce": entry.nonce, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "auth_time": now.Unix(), "email": "not-a-membership-proof@example.com"}).Serialize()
			if err != nil {
				http.Error(w, "fixture token", 500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": token, "token_type": "Bearer", "access_token": "unused-upstream-access-token"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

type browser struct {
	handler http.Handler
	cookies map[string]*http.Cookie
}

func (b *browser) request(method, target, body, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return w
}
func (b *browser) clone() *browser {
	cookies := map[string]*http.Cookie{}
	for k, v := range b.cookies {
		copy := *v
		cookies[k] = &copy
	}
	return &browser{b.handler, cookies}
}
func browserStart(t *testing.T, b *browser, f *oidcFixture) string {
	t.Helper()
	q := url.Values{"client_id": {"web"}, "response_type": {"code"}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "resource": {"https://api.example"}, "scope": {"read"}, "state": {"downstream-state-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}}
	w := b.request("GET", "/t/a/authorize?"+q.Encode(), "", "")
	if w.Code != 303 {
		t.Fatal("start browser login", w.Code, w.Body.String())
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Get(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 303 {
		t.Fatal("upstream fixture", r.StatusCode)
	}
	return r.Header.Get("Location")
}
func TestP2BrowserOIDCConsentAndSessionLifecycle(t *testing.T) {
	e, _, _, _ := setupAuthorization(t)
	f := newOIDCFixture(t)
	e.config = app.Config{PublicOrigin: "https://auth.example", AllowInsecureLoopback: true, Tenants: []app.TenantConfig{{ID: "a"}}}
	e.config.Tenants[0].IdentityProvider = &app.IdentityProviderConfig{ID: "upstream", Issuer: f.server.URL, ClientID: "mayi", ClientSecretEnv: "MAYI_A_IDP_SECRET", AuthorizationEndpoint: f.server.URL + "/authorize", TokenEndpoint: f.server.URL + "/token", JWKSURI: f.server.URL + "/jwks", SigningAlgorithm: "ES256"}
	e.secret["MAYI_A_IDP_SECRET"] = "fixture-secret"
	_, err := e.admin.Exec(context.Background(), `UPDATE mayi.clients SET name='Client <script>alert(1)</script>' WHERE tenant_id='a' AND client_id='web';UPDATE mayi.resource_scopes SET description='Read <items>' WHERE tenant_id='a' AND resource_id='api' AND name='read'`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.admin.Exec(context.Background(), `INSERT INTO mayi.external_identities VALUES('a','upstream',$1,'upstream-alice','user:alice')`, f.server.URL); err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewBrowser(context.Background(), e.config, e.config.Tenants[0], e.store, func(name string) string { return e.secret[name] })
	if err != nil {
		t.Fatal(err)
	}
	observed := middleware.NewTelemetry(slog.New(slog.NewJSONHandler(&e.log, nil))).Wrap(handler)
	b := &browser{handler: observed, cookies: map[string]*http.Cookie{}}
	for _, target := range []string{"/t/a/authorize?client_id=web&client_id=other", "/t/a/authorize?response_type=token", "/t/a/authorize?code_challenge_method=plain"} {
		if w := b.request("GET", target, "", ""); w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatal("unsafe authorization redirect", w.Code)
		}
	}
	if w := b.request("HEAD", "/t/a/authorize", "", ""); w.Code != 400 {
		t.Fatal("HEAD started authorization", w.Code)
	}
	cb := browserStart(t, b, f)
	before := b.clone()
	for _, c := range b.cookies {
		if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode || !strings.HasPrefix(c.Name, "__Host-") {
			t.Fatal("unsafe browser cookie", c.Name)
		}
	}
	u, _ := url.Parse(cb)
	bad := *u
	v := bad.Query()
	v.Set("state", "wrong-state")
	bad.RawQuery = v.Encode()
	if w := before.request("GET", bad.String(), "", ""); w.Code != 400 {
		t.Fatal("login state accepted", w.Code)
	}
	if w := b.request("GET", cb, "", ""); w.Code != 303 || w.Header().Get("Location") != "/t/a/consent" {
		t.Fatal("OIDC callback", w.Code, w.Body.String())
	}
	session := b.cookies["__Host-mayi-session-a"]
	if session == nil {
		t.Fatal("no local session")
	}
	if w := before.request("GET", cb, "", ""); w.Code != 400 {
		t.Fatal("callback replay", w.Code)
	}
	w := b.request("GET", "/t/a/consent", "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") || !strings.Contains(w.Body.String(), "Read &lt;items&gt;") || w.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("unsafe consent rendering", w.Code, w.Body.String())
	}
	data, err := base64.RawURLEncoding.DecodeString(b.cookies["__Host-mayi-flow-a"].Value)
	if err != nil {
		t.Fatal(err)
	}
	var flow struct{ CSRF string }
	if json.Unmarshal(data, &flow) != nil {
		t.Fatal("flow cookie")
	}
	body := url.Values{"csrf": {flow.CSRF}, "decision": {"approve"}}.Encode()
	for _, origin := range []string{"", "https://evil.example", "null"} {
		if w := b.request("POST", "/t/a/consent", body, origin); w.Code != 400 {
			t.Fatal("foreign origin consent", origin, w.Code)
		}
	}
	wrongCSRF := url.Values{"csrf": {strings.Repeat("A", 43)}, "decision": {"approve"}}.Encode()
	if w := b.request("POST", "/t/a/consent", wrongCSRF, "https://auth.example"); w.Code != 400 {
		t.Fatal("wrong CSRF", w.Code)
	}
	replay := b.clone()
	w = b.request("POST", "/t/a/consent", body, "https://auth.example")
	if w.Code != 303 {
		t.Fatal("approve", w.Code, w.Body.String())
	}
	destination, _ := url.Parse(w.Header().Get("Location"))
	if destination.Scheme != "https" || destination.Host != "app.example" || destination.Query().Get("provider") != "mayi" || destination.Query().Get("state") != "downstream-state-123456" || destination.Query().Get("code") == "" || destination.Query().Get("iss") != "https://auth.example/t/a" {
		t.Fatal("authorization response", destination)
	}
	if w := replay.request("POST", "/t/a/consent", body, "https://auth.example"); w.Code != 400 {
		t.Fatal("consent replay", w.Code)
	}
	if w := b.request("POST", "/t/a/session/end", "", "https://evil.example"); w.Code != 400 {
		t.Fatal("cross-origin logout", w.Code)
	}
	if w := b.request("POST", "/t/a/session/end", "", "https://auth.example"); w.Code != 204 {
		t.Fatal("local session end", w.Code, w.Body.String())
	}
	var revoked bool
	if err := e.admin.QueryRow(context.Background(), `SELECT revoked FROM mayi.browser_sessions WHERE tenant_id='a' AND session_hash=$1`, secretHash(session.Value)).Scan(&revoked); err != nil || !revoked {
		t.Fatal("session survived termination", err)
	}
	var grants int
	if err := e.admin.QueryRow(context.Background(), `SELECT count(*) FROM mayi.grants WHERE tenant_id='a' AND NOT revoked`).Scan(&grants); err != nil || grants != 1 {
		t.Fatal("session end incorrectly revoked durable grant", err, grants)
	}
	for _, secret := range []string{session.Value, flow.CSRF, destination.Query().Get("code"), "fixture-secret", "unused-upstream-access-token"} {
		if strings.Contains(e.log.String(), secret) {
			t.Fatal("credential leaked to request log")
		}
	}
	if !strings.Contains(e.log.String(), "http_request") {
		t.Fatal("request logging was not exercised")
	}
}

func TestP2ServerMountsConfiguredBrowserRoutes(t *testing.T) {
	e := setupFoundation(t)
	f := newOIDCFixture(t)
	e.config.Tenants[0].IdentityProvider = &app.IdentityProviderConfig{ID: "upstream", Issuer: f.server.URL, ClientID: "mayi", ClientSecretEnv: "MAYI_A_IDP_SECRET", AuthorizationEndpoint: f.server.URL + "/authorize", TokenEndpoint: f.server.URL + "/token", JWKSURI: f.server.URL + "/jwks", SigningAlgorithm: "ES256"}
	e.secret["MAYI_A_IDP_SECRET"] = "fixture-secret"
	h := e.server(t).Handler
	if w := api(t, h, "GET", "/t/a/authorize", "", ""); w.Code != 400 || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("configured browser route missing", w.Code)
	}
	if w := api(t, h, "GET", "/t/b/authorize", "", ""); w.Code != 404 {
		t.Fatal("unconfigured tenant has login route", w.Code)
	}
	if w := api(t, h, "GET", "/t/a/jwks", "", ""); w.Code != 200 {
		t.Fatal("browser subtree hid public keys", w.Code)
	}
}
