package contract_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
)

func TestFositeOIDCCodeNonceIssuerAndAudience(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := &fosite.Config{GlobalSecret: bytes.Repeat([]byte{42}, 32), EnforcePKCE: true, IDTokenIssuer: "https://auth.example/t/a"}
	store := storage.NewMemoryStore()
	store.Clients["rp"] = &fosite.DefaultClient{ID: "rp", Public: true, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, RedirectURIs: []string{"https://rp.example/cb"}, Scopes: []string{"openid", "profile"}}
	oidc := compose.NewOpenIDConnectStrategy(func(context.Context) (interface{}, error) { return key, nil }, config)
	strategy := &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config), OpenIDConnectTokenStrategy: oidc, Signer: oidc.Signer}
	provider := compose.Compose(config, store, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OpenIDConnectExplicitFactory)
	nonce := "nonce-1234567890123456"
	form := url.Values{"client_id": {"rp"}, "response_type": {"code"}, "redirect_uri": {"https://rp.example/cb"}, "scope": {"openid profile"}, "state": {"state-123456789012345"}, "nonce": {nonce}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}}
	req, err := provider.NewAuthorizeRequest(context.Background(), httptest.NewRequest("GET", "https://auth.example/t/a/authorize?"+form.Encode(), nil))
	if err != nil {
		t.Fatal(err)
	}
	req.GrantScope("openid")
	req.GrantScope("profile")
	session := openid.NewDefaultSession()
	session.Subject = "user:alice"
	session.Claims.Subject = "user:alice"
	session.Claims.AuthTime = time.Now().UTC()
	session.Claims.RequestedAt = time.Now().UTC()
	auth, err := provider.NewAuthorizeResponse(context.Background(), req, session)
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"client_id": {"rp"}, "grant_type": {"authorization_code"}, "redirect_uri": {"https://rp.example/cb"}, "code": {auth.GetCode()}, "code_verifier": {verifier}}
	wire := httptest.NewRequest(http.MethodPost, "https://auth.example/t/a/token", strings.NewReader(values.Encode()))
	wire.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	access, err := provider.NewAccessRequest(context.Background(), wire, openid.NewDefaultSession())
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewAccessResponse(context.Background(), access)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := response.GetExtra("id_token").(string)
	if !ok || id == "" {
		t.Fatal("no ID token")
	}
	parsed, err := josejwt.ParseSigned(id)
	if err != nil {
		t.Fatal(err)
	}
	var claims josejwt.Claims
	var extra map[string]interface{}
	if err := parsed.Claims(&key.PublicKey, &claims, &extra); err != nil {
		t.Fatal(err)
	}
	if err := claims.Validate(josejwt.Expected{Issuer: config.IDTokenIssuer, Subject: "user:alice", Audience: josejwt.Audience{"rp"}, Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if extra["nonce"] != nonce || len(claims.Audience) != 1 || claims.Audience[0] != "rp" {
		t.Fatal("ID token lost nonce/client audience")
	}
	if claims.Audience.Contains("https://api.example") {
		t.Fatal("ID token accepted as business resource credential")
	}
	if parsed.Headers[0].Algorithm != string(jose.ES256) {
		t.Fatal("unexpected signature algorithm")
	}
}
