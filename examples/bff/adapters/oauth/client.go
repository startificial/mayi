// Package oauth uses the admitted Go OAuth client against fixed server endpoints.
package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/startificial/mayi/examples/bff/services"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var _ services.OAuthClient = (*Client)(nil)
var _ services.LoginClient = (*Client)(nil)

type Client struct {
	config oauth2.Config
	http   *http.Client
}

func New(issuer, client, secret, redirect, resource string, httpClient *http.Client) (*Client, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || client == "" || secret == "" || httpClient == nil || httpClient.Timeout <= 0 || httpClient.Timeout > 10*time.Second {
		return nil, services.ErrSession
	}
	aud, err := url.Parse(resource)
	if err != nil || aud.Scheme != "https" || aud.Host == "" || aud.User != nil || aud.RawQuery != "" || aud.Fragment != "" {
		return nil, services.ErrSession
	}
	copy := *httpClient
	transport := httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	copy.Transport = &resourceTransport{transport, issuer + "/token", resource}
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{config: oauth2.Config{ClientID: client, ClientSecret: secret, RedirectURL: redirect, Endpoint: oauth2.Endpoint{AuthURL: issuer + "/authorize", TokenURL: issuer + "/token", AuthStyle: oauth2.AuthStyleInHeader}}, http: &copy}, nil
}
func (c *Client) Refresh(ctx context.Context, refresh string) (services.Tokens, error) {
	if refresh == "" || len(refresh) > 256 {
		return services.Tokens{}, services.ErrSession
	}
	// The library token source is scoped to this single call. Application sessions
	// serialize and persist rotation; there is no process-global token cache.
	token, err := c.config.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, c.http), &oauth2.Token{RefreshToken: refresh}).Token()
	if err != nil {
		return services.Tokens{}, services.ErrSession
	}
	return convert(token)
}
func (c *Client) Exchange(ctx context.Context, code, verifier, resource string) (services.Tokens, error) {
	token, err := c.config.Exchange(context.WithValue(ctx, oauth2.HTTPClient, c.http), code, oauth2.VerifierOption(verifier), oauth2.SetAuthURLParam("resource", resource))
	if err != nil {
		return services.Tokens{}, services.ErrSession
	}
	return convert(token)
}
func convert(t *oauth2.Token) (services.Tokens, error) {
	if t == nil || t.AccessToken == "" || t.TokenType != "Bearer" || t.Expiry.IsZero() {
		return services.Tokens{}, errors.New("invalid OAuth response")
	}
	id, _ := t.Extra("id_token").(string)
	return services.Tokens{Access: t.AccessToken, Refresh: t.RefreshToken, Identity: id, Type: t.TokenType, ExpiresAt: t.Expiry}, nil
}

// resourceTransport supplies the configured RFC 8707 audience on refresh. The
// OAuth client library has no refresh-options argument. It may send only to the
// fixed token endpoint, and cannot silently retry client-auth discovery.
type resourceTransport struct {
	base               http.RoundTripper
	endpoint, resource string
}

func (t *resourceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	issuer := strings.TrimSuffix(t.endpoint, "/token")
	if r.Method == "GET" && r.URL.String() == issuer+"/jwks" {
		return t.base.RoundTrip(r)
	}
	if (r.URL.String() != t.endpoint && r.URL.String() != issuer+"/par") || r.Method != "POST" || r.Body == nil {
		return nil, services.ErrSession
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 128<<10+1))
	_ = r.Body.Close()
	if err != nil || len(body) > 128<<10 {
		return nil, services.ErrSession
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, services.ErrSession
	}
	if v, exists := values["resource"]; exists && (len(v) != 1 || v[0] != t.resource) {
		return nil, services.ErrSession
	}
	values.Set("resource", t.resource)
	copy := r.Clone(r.Context())
	data := values.Encode()
	copy.Body = io.NopCloser(strings.NewReader(data))
	copy.ContentLength = int64(len(data))
	copy.GetBody = nil
	return t.base.RoundTrip(copy)
}

func (c *Client) Begin(ctx context.Context, q services.AuthorizationRequest) (string, error) {
	details, err := json.Marshal([]map[string]any{{"type": q.Type, "locations": []string{c.http.Transport.(*resourceTransport).resource}, "identifier": q.Identifier, "actions": q.Actions}})
	if err != nil || len(details) > 32768 {
		return "", services.ErrSession
	}
	form := url.Values{"client_id": {c.config.ClientID}, "response_type": {"code"}, "redirect_uri": {c.config.RedirectURL}, "resource": {c.http.Transport.(*resourceTransport).resource}, "scope": {q.Permission + " openid offline_access"}, "state": {q.State}, "nonce": {q.Nonce}, "code_challenge_method": {"S256"}, "code_challenge": {oauth2.S256ChallengeFromVerifier(q.Verifier)}, "authorization_details": {string(details)}}
	issuer := strings.TrimSuffix(c.config.Endpoint.TokenURL, "/token")
	r, err := http.NewRequestWithContext(ctx, "POST", issuer+"/par", strings.NewReader(form.Encode()))
	if err != nil {
		return "", services.ErrSession
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(c.config.ClientID), url.QueryEscape(c.config.ClientSecret))
	response, err := c.http.Do(r)
	if err != nil {
		return "", services.ErrSession
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(body) > 8192 || response.StatusCode != 201 {
		return "", services.ErrSession
	}
	var value struct {
		URI     string `json:"request_uri"`
		Seconds int    `json:"expires_in"`
	}
	if json.Unmarshal(body, &value) != nil || value.Seconds < 1 || value.Seconds > 90 || !strings.HasPrefix(value.URI, "urn:ietf:params:oauth:request_uri:") || len(value.URI) != len("urn:ietf:params:oauth:request_uri:")+43 {
		return "", services.ErrSession
	}
	return issuer + "/authorize?" + url.Values{"client_id": {c.config.ClientID}, "request_uri": {value.URI}}.Encode(), nil
}
func (c *Client) ExchangeIdentity(ctx context.Context, code string, m services.LoginMaterial) (services.Tokens, error) {
	tokens, err := c.Exchange(ctx, code, m.Verifier, c.http.Transport.(*resourceTransport).resource)
	if err != nil {
		return services.Tokens{}, services.ErrSession
	}
	if tokens.Identity == "" || len(tokens.Identity) > 65536 {
		return services.Tokens{}, services.ErrSession
	}
	parsed, err := jwt.ParseSigned(tokens.Identity, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(parsed.Headers) != 1 || parsed.Headers[0].KeyID == "" || parsed.Headers[0].ExtraHeaders["typ"] != "JWT" || parsed.Headers[0].JSONWebKey != nil {
		return services.Tokens{}, services.ErrSession
	}
	for key := range parsed.Headers[0].ExtraHeaders {
		if key != "typ" {
			return services.Tokens{}, services.ErrSession
		}
	}
	issuer := strings.TrimSuffix(c.config.Endpoint.TokenURL, "/token")
	r, err := http.NewRequestWithContext(ctx, "GET", issuer+"/jwks", nil)
	if err != nil {
		return services.Tokens{}, services.ErrSession
	}
	response, err := c.http.Do(r)
	if err != nil {
		return services.Tokens{}, services.ErrSession
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || len(body) > 32768 || response.StatusCode != 200 {
		return services.Tokens{}, services.ErrSession
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(body, &keys) != nil || len(keys.Keys) < 1 || len(keys.Keys) > 16 {
		return services.Tokens{}, services.ErrSession
	}
	matches := keys.Key(parsed.Headers[0].KeyID)
	if len(matches) != 1 {
		return services.Tokens{}, services.ErrSession
	}
	key := matches[0]
	ec, ok := key.Key.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() || !key.Valid() || !key.IsPublic() || key.Use != "sig" || key.Algorithm != "ES256" {
		return services.Tokens{}, services.ErrSession
	}
	var claims jwt.Claims
	var extra struct {
		Nonce         string `json:"nonce"`
		Authenticated int64  `json:"auth_time"`
	}
	if parsed.Claims(key.Key, &claims, &extra) != nil {
		return services.Tokens{}, services.ErrSession
	}
	now := time.Now()
	if claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer, AnyAudience: jwt.Audience{c.config.ClientID}, Time: now}, 5*time.Second) != nil || claims.Subject == "" || len(claims.Audience) != 1 || claims.IssuedAt == nil || claims.Expiry == nil || claims.Expiry.Time().After(claims.IssuedAt.Time().Add(15*time.Minute)) || subtle.ConstantTimeCompare([]byte(extra.Nonce), []byte(m.Nonce)) != 1 || extra.Authenticated < m.CreatedAt.Add(-5*time.Second).Unix() || extra.Authenticated > claims.IssuedAt.Time().Add(5*time.Second).Unix() {
		return services.Tokens{}, services.ErrSession
	}
	return tokens, nil
}
