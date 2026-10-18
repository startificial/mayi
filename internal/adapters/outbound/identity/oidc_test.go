package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/startificial/mayi/internal/services/authentication"
	"net/url"
	"testing"
	"time"
)

type transport struct {
	metadata, keys, response []byte
	gets                     []string
	fields                   []authentication.FormField
}

func (t *transport) GetJSON(_ context.Context, u string) ([]byte, error) {
	t.gets = append(t.gets, u)
	if u == "https://idp.example/.well-known/openid-configuration" {
		return t.metadata, nil
	}
	if u == "https://idp.example/jwks" {
		return t.keys, nil
	}
	return nil, errors.New("unexpected URL")
}
func (t *transport) PostForm(_ context.Context, u string, f []authentication.FormField, id, secret string) ([]byte, error) {
	if u != "https://idp.example/token" || id != "mayi" || secret != "test-secret" {
		return nil, errors.New("wrong credential destination")
	}
	t.fields = f
	return t.response, nil
}
func providerFixture(t *testing.T) (*OIDC, *transport, *ecdsa.PrivateKey, time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := &transport{metadata: []byte(`{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token","jwks_uri":"https://idp.example/jwks","response_types_supported":["code"],"id_token_signing_alg_values_supported":["ES256"],"token_endpoint_auth_methods_supported":["client_secret_basic"],"code_challenge_methods_supported":["S256"]}`)}
	x.keys, _ = json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "upstream-key", Algorithm: "ES256", Use: "sig"}}})
	p, err := New(context.Background(), Config{ID: "provider", Issuer: "https://idp.example", ClientID: "mayi", ClientSecret: "test-secret", RedirectURI: "https://auth.example/t/a/upstream/callback", AuthorizationEndpoint: "https://idp.example/authorize", TokenEndpoint: "https://idp.example/token", JWKSURI: "https://idp.example/jwks", SigningAlgorithm: "ES256"}, x)
	if err != nil {
		t.Fatal(err)
	}
	return p, x, key, time.Now().UTC().Truncate(time.Second)
}
func setResponse(t *testing.T, x *transport, key *ecdsa.PrivateKey, claims map[string]any, extra map[jose.HeaderKey]any) {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithHeader("kid", "upstream-key").WithType("JWT")
	for k, v := range extra {
		opts.WithHeader(k, v)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	x.response, _ = json.Marshal(map[string]string{"id_token": token, "access_token": "unused-upstream-token", "token_type": "Bearer"})
}
func TestProviderVerifiesIdentityWithoutTokenControlledFetch(t *testing.T) {
	for _, mode := range []string{"valid", "issuer", "audience", "azp", "nonce", "expired", "missing exp", "missing iat", "missing auth_time", "stale authentication", "future authentication", "wrong signature", "jku", "access-token type"} {
		t.Run(mode, func(t *testing.T) {
			p, x, key, now := providerFixture(t)
			claims := map[string]any{"iss": "https://idp.example", "sub": "alice", "aud": "mayi", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "auth_time": now.Unix(), "nonce": "nonce"}
			extra := map[jose.HeaderKey]any{}
			switch mode {
			case "issuer":
				claims["iss"] = "https://evil.example"
			case "audience":
				claims["aud"] = "other"
			case "azp":
				claims["azp"] = "other"
			case "nonce":
				claims["nonce"] = "other"
			case "expired":
				claims["exp"] = now.Add(-time.Minute).Unix()
			case "missing exp":
				delete(claims, "exp")
			case "missing iat":
				delete(claims, "iat")
			case "missing auth_time":
				delete(claims, "auth_time")
			case "stale authentication":
				claims["auth_time"] = now.Add(-10 * time.Minute).Unix()
			case "future authentication":
				claims["auth_time"] = now.Add(time.Minute).Unix()
			case "wrong signature":
				key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			case "jku":
				extra["jku"] = "https://evil.example/key"
			case "access-token type":
				extra["typ"] = "at+jwt"
			}
			setResponse(t, x, key, claims, extra)
			result, err := p.Authenticate(context.Background(), "code", "nonce", "verifier", now)
			if mode == "valid" {
				if err != nil || result.Subject != "alice" {
					t.Fatal(result, err)
				}
			} else if !errors.Is(err, authentication.ErrDenied) || result.Subject != "" {
				t.Fatal("invalid ID token accepted", result, err)
			}
			for _, u := range x.gets {
				if u != "https://idp.example/.well-known/openid-configuration" && u != "https://idp.example/jwks" {
					t.Fatal("untrusted fetch", u)
				}
			}
		})
	}
}
func TestUpstreamAuthorizationAndAmbiguousJSON(t *testing.T) {
	p, _, _, _ := providerFixture(t)
	raw, err := p.AuthorizationURL("state", "nonce", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if q.Get("nonce") != "nonce" || q.Get("code_challenge_method") != "S256" || q.Get("max_age") != "0" || q.Get("redirect_uri") != p.config.RedirectURI {
		t.Fatal(q)
	}
	for _, raw := range []string{`{"iss":"a","iss":"b"}`, `{"keys":[{"kid":"a","kid":"b"}]}`, `{} {}`, `[}`} {
		if decode([]byte(raw), &map[string]any{}) == nil {
			t.Fatal("ambiguous JSON accepted", raw)
		}
	}
}

func TestProviderMetadataMustMatchExplicitTrust(t *testing.T) {
	for _, mode := range []string{"issuer", "token_endpoint", "jwks_uri", "code_challenge_methods_supported", "id_token_signing_alg_values_supported", "token_endpoint_auth_methods_supported"} {
		t.Run(mode, func(t *testing.T) {
			p, x, _, _ := providerFixture(t)
			var metadata map[string]any
			if json.Unmarshal(x.metadata, &metadata) != nil {
				t.Fatal("fixture metadata")
			}
			switch mode {
			case "issuer", "token_endpoint", "jwks_uri":
				metadata[mode] = "https://evil.example"
			default:
				metadata[mode] = []string{"unsupported"}
			}
			x.metadata, _ = json.Marshal(metadata)
			if _, err := New(context.Background(), p.config, x); !errors.Is(err, authentication.ErrUnavailable) {
				t.Fatal("untrusted metadata accepted", err)
			}
		})
	}
}
