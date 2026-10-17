package contract_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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
	"github.com/ory/fosite/storage"
	fositejwt "github.com/ory/fosite/token/jwt"
)

// Candidate-only protocol storage: never a production fallback. Application
// transaction behavior is tested separately against the service-owned UoW.
type protocolFixture struct {
	provider fosite.OAuth2Provider
	store    *storage.MemoryStore
}
type grantSession struct {
	fosite.DefaultSession
	GrantID              string
	Revision             uint64
	Resource, Thumbprint string
}

func (s *grantSession) Clone() fosite.Session {
	copy := *s
	copy.DefaultSession = *(s.DefaultSession.Clone().(*fosite.DefaultSession))
	return &copy
}

func newProtocolFixture(t *testing.T) *protocolFixture {
	t.Helper()
	config := &fosite.Config{GlobalSecret: bytes.Repeat([]byte{0x42}, 32), EnforcePKCE: true, AuthorizeCodeLifespan: time.Minute, AccessTokenLifespan: 5 * time.Minute, RefreshTokenScopes: []string{"offline"}, TokenURL: "https://auth.example/t/a/token"}
	store := storage.NewMemoryStore()
	store.Clients["client:public"] = &fosite.DefaultClient{ID: "client:public", Public: true, RedirectURIs: []string{"https://client.example/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, Scopes: []string{"read", "offline"}, Audience: []string{"https://api.example/a"}}
	provider := compose.Compose(config, store, compose.NewOAuth2HMACStrategy(config), compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2RefreshTokenGrantFactory, compose.OAuth2ClientCredentialsGrantFactory)
	return &protocolFixture{provider: provider, store: store}
}
func authorizeCandidate(f *protocolFixture, method, challengeValue, responseType string) (string, error) {
	values := url.Values{"client_id": {"client:public"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {responseType}, "state": {"12345678901234567890"}, "scope": {"read offline"}, "audience": {"https://api.example/a"}}
	if method != "" {
		values.Set("code_challenge_method", method)
	}
	if challengeValue != "" {
		values.Set("code_challenge", challengeValue)
	}
	request, err := f.provider.NewAuthorizeRequest(context.Background(), httptest.NewRequest(http.MethodGet, "https://auth.example/t/a/authorize?"+values.Encode(), nil))
	if err != nil {
		return "", err
	}
	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}
	request.GrantAudience("https://api.example/a")
	response, err := f.provider.NewAuthorizeResponse(context.Background(), request, &grantSession{DefaultSession: fosite.DefaultSession{Subject: "user:alice"}, GrantID: "grant-original", Revision: 7, Resource: "https://api.example/a", Thumbprint: "original-dpop-key"})
	if err != nil {
		return "", err
	}
	return response.GetCode(), nil
}
func candidateTokenRequest(f *protocolFixture, form url.Values) (fosite.AccessRequester, fosite.AccessResponder, error) {
	request := httptest.NewRequest(http.MethodPost, "https://auth.example/t/a/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	access, err := f.provider.NewAccessRequest(context.Background(), request, &grantSession{})
	if err != nil {
		return nil, nil, err
	}
	response, err := f.provider.NewAccessResponse(context.Background(), access)
	return access, response, err
}
func TestFositeCodeS256AndGrantCorrelation(t *testing.T) {
	f := newProtocolFixture(t)
	code, err := authorizeCandidate(f, "S256", challenge, "code")
	if err != nil {
		t.Fatal(err)
	}
	access, response, err := candidateTokenRequest(f, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"client:public"}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatal(err)
	}
	session, ok := access.GetSession().(*grantSession)
	if !ok || session.GrantID != "grant-original" || session.Revision != 7 || session.Resource != "https://api.example/a" || session.Thumbprint != "original-dpop-key" {
		t.Fatalf("grant correlation lost: %+v", session)
	}
	refresh, _ := response.GetExtra("refresh_token").(string)
	if refresh == "" {
		t.Fatal("missing refresh token")
	}
	next, _, err := candidateTokenRequest(f, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"client:public"}, "scope": {"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if s := next.GetSession().(*grantSession); s.Revision != 7 || s.GrantID != "grant-original" || s.Thumbprint != "original-dpop-key" {
		t.Fatal("refresh lost original grant/binding")
	}
}
func TestFositeRejectsMissingAndPlainPKCEAndRemovedFlows(t *testing.T) {
	for name, values := range map[string][3]string{"missing": {"", "", "code"}, "plain": {"plain", verifier, "code"}, "implicit": {"S256", challenge, "token"}, "hybrid": {"S256", challenge, "code token"}} {
		t.Run(name, func(t *testing.T) {
			if _, err := authorizeCandidate(newProtocolFixture(t), values[0], values[1], values[2]); err == nil {
				t.Fatal("unsafe authorization accepted")
			}
		})
	}
	f := newProtocolFixture(t)
	if _, _, err := candidateTokenRequest(f, url.Values{"grant_type": {"password"}, "client_id": {"client:public"}, "username": {"alice"}, "password": {"unused"}}); err == nil {
		t.Fatal("password grant accepted")
	}
}
func TestFositeWrongVerifierAndRedirectFail(t *testing.T) {
	for _, field := range []string{"code_verifier", "redirect_uri"} {
		t.Run(field, func(t *testing.T) {
			f := newProtocolFixture(t)
			code, err := authorizeCandidate(f, "S256", challenge, "code")
			if err != nil {
				t.Fatal(err)
			}
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"client:public"}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {verifier}}
			form.Set(field, "wrong")
			if _, _, err := candidateTokenRequest(f, form); err == nil {
				t.Fatal("mismatched credential accepted")
			}
		})
	}
}
func TestFositePrivateKeyJWTInlineKeyAndReplay(t *testing.T) {
	f := newProtocolFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.store.Clients["client:machine"] = &fosite.DefaultOpenIDConnectClient{DefaultClient: &fosite.DefaultClient{ID: "client:machine", GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"}, Audience: []string{"https://api.example/a"}}, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlgorithm: "ES256", JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "ES256", Use: "sig"}}}}
	sign, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	assertion, err := josejwt.Signed(sign).Claims(josejwt.Claims{Issuer: "client:machine", Subject: "client:machine", Audience: josejwt.Audience{"https://auth.example/t/a/token"}, IssuedAt: josejwt.NewNumericDate(now), Expiry: josejwt.NewNumericDate(now.Add(time.Minute)), ID: "unique-client-assertion"}).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"client:machine"}, "scope": {"read"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}}
	if _, _, err := candidateTokenRequest(f, form); err != nil {
		t.Fatal(err)
	}
	if _, _, err := candidateTokenRequest(f, form); err == nil {
		t.Fatal("client assertion replay accepted")
	}
}

type publicOnlyOpaque struct{ key *ecdsa.PrivateKey }

func (s publicOnlyOpaque) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: &s.key.PublicKey, Algorithm: "ES256"}
}
func (publicOnlyOpaque) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}
func (publicOnlyOpaque) SignPayload([]byte, jose.SignatureAlgorithm) ([]byte, error) {
	return nil, errors.New("must not request local private key")
}
func TestFositeDefaultSignerDoesNotSupportPublicOnlyOpaqueKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := &fositejwt.DefaultSigner{GetPrivateKey: func(context.Context) (interface{}, error) { return publicOnlyOpaque{key}, nil }}
	if _, _, err := sign.Generate(context.Background(), fositejwt.MapClaims{"sub": "user:alice"}, &fositejwt.Headers{}); err == nil {
		t.Fatal("default signer unexpectedly accepted public-only opaque key; re-evaluate custom signer decision")
	}
}
