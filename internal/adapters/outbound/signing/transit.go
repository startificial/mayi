// Package signing implements remote, non-exportable signing through OpenBao Transit.
package signing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/startificial/mayi/internal/domain/grants"
	domaintokens "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.Signer = (*Transit)(nil)

// Config is trusted startup configuration. Token is a scoped service credential,
// never a token from an OAuth request. HTTP is allowed only for loopback P0 tests.
type Config struct {
	Address, Key, Token string
	Version             int
	Scope               grants.Scope
	AllowLoopbackHTTP   bool
}

type Transit struct {
	config         Config
	client         *http.Client
	public         jose.JSONWebKey
	minimumVersion int
}

func New(ctx context.Context, c Config, client *http.Client) (*Transit, error) {
	u, err := url.Parse(c.Address)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.Host == "" ||
		(u.Scheme != "https" && !(c.AllowLoopbackHTTP && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) ||
		!regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(c.Key) || c.Version < 1 || !c.Scope.Valid() || c.Token == "" || client == nil || client.Timeout <= 0 || client.Timeout > 30*time.Second {
		return nil, tokens.ErrUnavailable
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s := &Transit{config: c, client: &copyClient}
	var metadata struct {
		Data struct {
			Type           string `json:"type"`
			Exportable     *bool  `json:"exportable"`
			Backup         *bool  `json:"allow_plaintext_backup"`
			MinimumVersion *int   `json:"min_encryption_version"`
			Keys           map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := s.request(ctx, http.MethodGet, "keys/"+c.Key, nil, &metadata); err != nil {
		return nil, err
	}
	if metadata.Data.MinimumVersion == nil || *metadata.Data.MinimumVersion < 0 || metadata.Data.Type != "ecdsa-p256" || metadata.Data.Exportable == nil || metadata.Data.Backup == nil || *metadata.Data.Exportable || *metadata.Data.Backup {
		return nil, tokens.ErrUnavailable
	}
	block, rest := pem.Decode([]byte(metadata.Data.Keys[strconv.Itoa(c.Version)].PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, tokens.ErrUnavailable
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, tokens.ErrUnavailable
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, tokens.ErrUnavailable
	}
	s.minimumVersion = *metadata.Data.MinimumVersion
	s.public = jose.JSONWebKey{Key: ec, KeyID: c.Key + ".v" + strconv.Itoa(c.Version), Algorithm: string(jose.ES256), Use: "sig"}
	return s, nil
}

// JWKS contains only the configured public key. Rotation is explicit: create a
// second signer version and retain old public keys through their token lifetime.
func (s *Transit) JWKS() ([]byte, error) {
	return json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{s.public.Public()}})
}

func (s *Transit) request(ctx context.Context, method, path string, body any, result any) error {
	var input bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&input).Encode(body); err != nil {
			return tokens.ErrUnavailable
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, s.config.Address+"/v1/transit/"+path, &input)
	if err != nil {
		return tokens.ErrUnavailable
	}
	r.Header.Set("X-Vault-Token", s.config.Token)
	r.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(r)
	if err != nil {
		return tokens.ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return tokens.ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(b) > 1<<20 || json.Unmarshal(b, result) != nil {
		return tokens.ErrUnavailable
	}
	return nil
}

func (s *Transit) SignAccessToken(ctx context.Context, c domaintokens.AccessClaims) (string, error) {
	if c.Scope != s.config.Scope || c.ID == "" || c.Resource == "" || c.Subject == "" || c.ClientID == "" || c.GrantID == "" || c.Revision == 0 || (c.PrincipalType != "user" && c.PrincipalType != "machine") || len(c.Scopes) == 0 || !grants.ValidScopes(c.Scopes) || c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.After(c.IssuedAt.Add(15*time.Minute)) {
		return "", tokens.ErrUnavailable
	}
	var details []objectDetailClaim
	if !c.ObjectCeiling.IsZero() {
		if !c.ObjectCeiling.BoundTo(c.Scope, c.Resource) || len(c.ObjectCeiling.Snapshot().Details) == 0 {
			return "", tokens.ErrUnavailable
		}
		for _, d := range c.ObjectCeiling.Snapshot().Details {
			details = append(details, objectDetailClaim{Type: d.Type, Locations: []string{c.Resource}, Identifier: d.Identifier, Actions: d.Actions})
		}
		data, err := json.Marshal(details)
		if err != nil || len(data) > 32<<10 {
			return "", tokens.ErrUnavailable
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: &remoteSigner{transit: s, ctx: ctx}}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", s.public.KeyID))
	if err != nil {
		return "", tokens.ErrUnavailable
	}
	claims := map[string]any{"iss": c.Scope.Issuer, "tenant_id": c.Scope.TenantID, "sub": c.Subject, "aud": c.Resource, "client_id": c.ClientID, "jti": c.ID, "iat": c.IssuedAt.Unix(), "exp": c.ExpiresAt.Unix(), "scope": strings.Join(c.Scopes, " "), "principal_type": c.PrincipalType, "grant_id": c.GrantID, "grant_revision": c.Revision}
	if details != nil {
		claims["authorization_details"] = details
	}
	if c.BindingThumbprint != "" {
		claims["cnf"] = map[string]string{"jkt": c.BindingThumbprint}
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", tokens.ErrUnavailable
	}
	return token, nil
}

// Only the standard RFC 9396 fields enter the signed claim. Profiles are
// checked by the token service before signing; no adapter-owned policy applies.
type objectDetailClaim struct {
	Type       string   `json:"type"`
	Locations  []string `json:"locations"`
	Identifier string   `json:"identifier"`
	Actions    []string `json:"actions"`
}

type remoteSigner struct {
	transit *Transit
	ctx     context.Context
}

func (r *remoteSigner) Public() *jose.JSONWebKey      { key := r.transit.public.Public(); return &key }
func (*remoteSigner) Algs() []jose.SignatureAlgorithm { return []jose.SignatureAlgorithm{jose.ES256} }
func (r *remoteSigner) SignPayload(payload []byte, algorithm jose.SignatureAlgorithm) ([]byte, error) {
	if algorithm != jose.ES256 {
		return nil, tokens.ErrUnavailable
	}
	var response struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	body := map[string]any{"input": base64.StdEncoding.EncodeToString(payload), "key_version": r.transit.config.Version, "hash_algorithm": "sha2-256", "prehashed": false, "marshaling_algorithm": "jws"}
	if err := r.transit.request(r.ctx, http.MethodPost, "sign/"+r.transit.config.Key, body, &response); err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("vault:v%d:", r.transit.config.Version)
	if !strings.HasPrefix(response.Data.Signature, prefix) {
		return nil, tokens.ErrUnavailable
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(response.Data.Signature, prefix))
	if err != nil || len(signature) != 64 {
		return nil, tokens.ErrUnavailable
	}
	return signature, nil
}
