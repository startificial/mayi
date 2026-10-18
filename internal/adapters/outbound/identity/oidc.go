// Package identity translates a configured OIDC provider's evidence to local
// identity values. It does not link accounts or decide tenant membership.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	domain "github.com/startificial/mayi/internal/domain/identity"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/authentication"
)

var _ authentication.Provider = (*OIDC)(nil)

type Config struct {
	ID, Issuer, ClientID, ClientSecret, RedirectURI, AuthorizationEndpoint, TokenEndpoint, JWKSURI string
	SigningAlgorithm                                                                               string
}
type OIDC struct {
	config    Config
	transport authentication.UpstreamTransport
}

func New(ctx context.Context, c Config, transport authentication.UpstreamTransport) (*OIDC, error) {
	if !resources.ValidID(c.ID) || c.ClientID == "" || len(c.ClientID) > 255 || c.ClientSecret == "" || len(c.ClientSecret) > 4096 || transport == nil || !slices.Contains([]string{"ES256", "RS256", "PS256"}, c.SigningAlgorithm) {
		return nil, authentication.ErrUnavailable
	}
	for _, raw := range []string{c.Issuer, c.RedirectURI, c.AuthorizationEndpoint, c.TokenEndpoint, c.JWKSURI} {
		u, e := url.Parse(raw)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "https" && u.Scheme != "http") || u.String() != raw {
			return nil, authentication.ErrUnavailable
		}
	}
	data, err := transport.GetJSON(ctx, strings.TrimSuffix(c.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, authentication.ErrUnavailable
	}
	var m struct {
		Issuer        string   `json:"issuer"`
		Authorization string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		JWKS          string   `json:"jwks_uri"`
		ResponseTypes []string `json:"response_types_supported"`
		Algorithms    []string `json:"id_token_signing_alg_values_supported"`
		Methods       []string `json:"token_endpoint_auth_methods_supported"`
		PKCE          []string `json:"code_challenge_methods_supported"`
	}
	if !requiredMembers(data, "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "response_types_supported", "id_token_signing_alg_values_supported", "code_challenge_methods_supported") || decode(data, &m) != nil || m.Issuer != c.Issuer || m.Authorization != c.AuthorizationEndpoint || m.Token != c.TokenEndpoint || m.JWKS != c.JWKSURI || !slices.Contains(m.ResponseTypes, "code") || !slices.Contains(m.Algorithms, c.SigningAlgorithm) || len(m.Methods) > 0 && !slices.Contains(m.Methods, "client_secret_basic") || !slices.Contains(m.PKCE, "S256") {
		return nil, authentication.ErrUnavailable
	}
	return &OIDC{config: c, transport: transport}, nil
}
func (p *OIDC) ID() string { return p.config.ID }
func (p *OIDC) Fingerprint() string {
	c := p.config
	c.ClientSecret = ""
	data, _ := json.Marshal(c)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
func (p *OIDC) AuthorizationURL(state, nonce, verifier string) (string, error) {
	u, err := url.Parse(p.config.AuthorizationEndpoint)
	if err != nil {
		return "", authentication.ErrUnavailable
	}
	h := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {p.config.ClientID}, "redirect_uri": {p.config.RedirectURI}, "response_type": {"code"}, "response_mode": {"query"}, "scope": {"openid"}, "state": {state}, "nonce": {nonce}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(h[:])}, "max_age": {"0"}, "prompt": {"login"}}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (p *OIDC) Authenticate(ctx context.Context, code, nonce, verifier string, now time.Time) (domain.Assertion, error) {
	data, err := p.transport.PostForm(ctx, p.config.TokenEndpoint, []authentication.FormField{{Name: "grant_type", Value: "authorization_code"}, {Name: "code", Value: code}, {Name: "redirect_uri", Value: p.config.RedirectURI}, {Name: "code_verifier", Value: verifier}}, p.config.ClientID, p.config.ClientSecret)
	if err != nil {
		return domain.Assertion{}, authentication.ErrUnavailable
	}
	var response struct {
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if !requiredMembers(data, "id_token", "access_token", "token_type") || decode(data, &response) != nil || response.Error != "" || !strings.EqualFold(response.TokenType, "Bearer") || response.AccessToken == "" || len(response.IDToken) > 16<<10 {
		return domain.Assertion{}, authentication.ErrDenied
	}
	parts := strings.Split(response.IDToken, ".")
	if len(parts) != 3 {
		return domain.Assertion{}, authentication.ErrDenied
	}
	protected, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || !requiredMembers(protected, "alg", "kid") {
		return domain.Assertion{}, authentication.ErrDenied
	}
	token, err := jwt.ParseSigned(response.IDToken, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(p.config.SigningAlgorithm)})
	if err != nil || len(token.Headers) != 1 {
		return domain.Assertion{}, authentication.ErrDenied
	}
	header := token.Headers[0]
	if header.KeyID == "" || header.JSONWebKey != nil {
		return domain.Assertion{}, authentication.ErrDenied
	}
	// Never fetch a header's jku/x5u or embedded key, even if the signature is valid.
	for name := range header.ExtraHeaders {
		if name != "typ" || header.ExtraHeaders[name] != "JWT" {
			return domain.Assertion{}, authentication.ErrDenied
		}
	}
	keys, err := p.transport.GetJSON(ctx, p.config.JWKSURI)
	if err != nil {
		return domain.Assertion{}, authentication.ErrUnavailable
	}
	var set jose.JSONWebKeySet
	if decode(keys, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > 32 {
		return domain.Assertion{}, authentication.ErrDenied
	}
	matches := set.Key(header.KeyID)
	if len(matches) != 1 {
		return domain.Assertion{}, authentication.ErrDenied
	}
	key := matches[0]
	if !key.IsPublic() || !key.Valid() || key.Use != "" && key.Use != "sig" || key.Algorithm != "" && key.Algorithm != p.config.SigningAlgorithm {
		return domain.Assertion{}, authentication.ErrDenied
	}
	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 || p.config.SigningAlgorithm == "ES256" {
			return domain.Assertion{}, authentication.ErrDenied
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() || p.config.SigningAlgorithm != "ES256" {
			return domain.Assertion{}, authentication.ErrDenied
		}
	default:
		return domain.Assertion{}, authentication.ErrDenied
	}
	var claims struct {
		jwt.Claims
		Nonce           string           `json:"nonce"`
		AuthorizedParty string           `json:"azp"`
		AuthTime        *jwt.NumericDate `json:"auth_time"`
		AccessHash      string           `json:"at_hash"`
	}
	// Check duplicate members in the signed payload, too, before interpreting it.
	parts = strings.Split(response.IDToken, ".")
	if len(parts) != 3 {
		return domain.Assertion{}, authentication.ErrDenied
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !requiredMembers(payload, "iss", "sub", "aud", "exp", "iat", "nonce", "auth_time") {
		return domain.Assertion{}, authentication.ErrDenied
	}
	if token.Claims(key.Key, &claims) != nil || claims.ValidateWithLeeway(jwt.Expected{Issuer: p.config.Issuer, AnyAudience: jwt.Audience{p.config.ClientID}, Time: now}, 30*time.Second) != nil || claims.Expiry == nil || claims.IssuedAt == nil || claims.AuthTime == nil || claims.IssuedAt.Time().After(now.Add(30*time.Second)) || claims.IssuedAt.Time().Before(now.Add(-5*time.Minute)) || claims.Expiry.Time().Before(claims.IssuedAt.Time()) || claims.Nonce != nonce || len(claims.Audience) != 1 || claims.AuthorizedParty != "" && claims.AuthorizedParty != p.config.ClientID {
		return domain.Assertion{}, authentication.ErrDenied
	}
	if claims.AccessHash != "" {
		h := sha256.Sum256([]byte(response.AccessToken))
		if claims.AccessHash != base64.RawURLEncoding.EncodeToString(h[:len(h)/2]) {
			return domain.Assertion{}, authentication.ErrDenied
		}
	}
	assertion := domain.Assertion{Issuer: claims.Issuer, Subject: claims.Subject, AuthenticatedAt: claims.AuthTime.Time()}
	if !assertion.ValidAt(now) {
		return domain.Assertion{}, authentication.ErrDenied
	}
	return assertion, nil
}
