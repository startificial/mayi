// Package crypto implements the application's encrypted credential boundary.
package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"time"

	"github.com/startificial/mayi/examples/bff/services"
)

var ErrCredentials = errors.New("encrypted credentials unavailable")
var _ services.CredentialCipher = (*Credentials)(nil)
var _ services.LoginSource = (*LoginSource)(nil)

type Key struct {
	ID     string
	Bytes  []byte
	Active bool
}

// Credentials uses AES-256-GCM from the Go standard library. Retained keys only
// decrypt; exactly one active key encrypts. The caller owns key delivery/storage.
type Credentials struct {
	active string
	keys   map[string]cipher.AEAD
}

func New(keys []Key) (*Credentials, error) {
	if len(keys) < 1 || len(keys) > 8 {
		return nil, ErrCredentials
	}
	c := &Credentials{keys: make(map[string]cipher.AEAD, len(keys))}
	for _, k := range keys {
		if !validID(k.ID) || len(k.Bytes) != 32 || c.keys[k.ID] != nil {
			return nil, ErrCredentials
		}
		block, err := aes.NewCipher(k.Bytes)
		if err != nil {
			return nil, ErrCredentials
		}
		aead, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, ErrCredentials
		}
		c.keys[k.ID] = aead
		if k.Active {
			if c.active != "" {
				return nil, ErrCredentials
			}
			c.active = k.ID
		}
	}
	if c.active == "" {
		return nil, ErrCredentials
	}
	return c, nil
}

func validID(s string) bool { return regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`).MatchString(s) }

func contextData(c services.CredentialContext, version uint32, keyID string) ([]byte, error) {
	if version != 1 || !validID(keyID) || !validID(c.Tenant) || !validID(c.Session) || c.Generation == 0 || len(c.Client) < 1 || len(c.Client) > 128 || (c.Purpose != "oauth-tokens" && c.Purpose != "login-state") {
		return nil, ErrCredentials
	}
	for _, value := range []string{c.Issuer, c.Resource} {
		u, err := url.Parse(value)
		if err != nil || len(value) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, ErrCredentials
		}
	}
	// Fixed-order JSON array gives unambiguous, length-delimited context encoding.
	// The domain separator and algorithm prevent cross-protocol/key-purpose reuse.
	data, err := json.Marshal([]any{"mayi-reference-bff", "AES-256-GCM", version, keyID, c.Tenant, c.Issuer, c.Client, c.Resource, c.Session, c.Purpose, c.Generation})
	if err != nil {
		return nil, ErrCredentials
	}
	return data, nil
}

func (c *Credentials) Seal(ctx context.Context, expected services.CredentialContext, plaintext []byte) (services.Envelope, error) {
	if ctx.Err() != nil || len(plaintext) == 0 || len(plaintext) > 128<<10 {
		return services.Envelope{}, ErrCredentials
	}
	data, err := contextData(expected, 1, c.active)
	if err != nil {
		return services.Envelope{}, ErrCredentials
	}
	// NewGCMWithRandomNonce generates and prepends its own 96-bit random nonce.
	sealed := c.keys[c.active].Seal(nil, nil, plaintext, data)
	return services.Envelope{Version: 1, KeyID: c.active, Ciphertext: sealed}, nil
}

func (c *Credentials) Open(ctx context.Context, expected services.CredentialContext, envelope services.Envelope) ([]byte, error) {
	if ctx.Err() != nil || len(envelope.Ciphertext) > 128<<10+28 {
		return nil, ErrCredentials
	}
	aead := c.keys[envelope.KeyID]
	if aead == nil || len(envelope.Ciphertext) < aead.Overhead()+1 {
		return nil, ErrCredentials
	}
	data, err := contextData(expected, envelope.Version, envelope.KeyID)
	if err != nil {
		return nil, ErrCredentials
	}
	plaintext, err := aead.Open(nil, nil, envelope.Ciphertext, data)
	if err != nil {
		return nil, ErrCredentials
	}
	return plaintext, nil
}

type tokenPayload struct {
	Access   string    `json:"access_token"`
	Refresh  string    `json:"refresh_token"`
	Identity string    `json:"id_token"`
	Type     string    `json:"token_type"`
	Expires  time.Time `json:"expires_at"`
}

func (c *Credentials) SealTokens(ctx context.Context, b services.CredentialContext, t services.Tokens) (services.Envelope, error) {
	data, err := json.Marshal(tokenPayload{t.Access, t.Refresh, t.Identity, t.Type, t.ExpiresAt})
	if err != nil {
		return services.Envelope{}, ErrCredentials
	}
	defer clear(data)
	return c.Seal(ctx, b, data)
}
func (c *Credentials) OpenTokens(ctx context.Context, b services.CredentialContext, e services.Envelope) (services.Tokens, error) {
	data, err := c.Open(ctx, b, e)
	if err != nil {
		return services.Tokens{}, ErrCredentials
	}
	defer clear(data)
	var value tokenPayload
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil || d.Decode(&struct{}{}) != io.EOF {
		return services.Tokens{}, ErrCredentials
	}
	return services.Tokens{Access: value.Access, Refresh: value.Refresh, Identity: value.Identity, Type: value.Type, ExpiresAt: value.Expires}, nil
}

type LoginSource struct{}

func NewLoginSource() *LoginSource { return &LoginSource{} }
func (*LoginSource) NewLogin(ctx context.Context) (services.LoginMaterial, error) {
	if ctx.Err() != nil {
		return services.LoginMaterial{}, ErrCredentials
	}
	var entropy [112]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return services.LoginMaterial{}, ErrCredentials
	}
	return services.LoginMaterial{ID: hex.EncodeToString(entropy[:16]), State: base64.RawURLEncoding.EncodeToString(entropy[16:48]), Nonce: base64.RawURLEncoding.EncodeToString(entropy[48:80]), Verifier: base64.RawURLEncoding.EncodeToString(entropy[80:])}, nil
}

type loginPayload struct {
	ID       string    `json:"id"`
	State    string    `json:"state"`
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"`
	Created  time.Time `json:"created_at"`
}

func (c *Credentials) SealLogin(ctx context.Context, b services.CredentialContext, m services.LoginMaterial) (services.Envelope, error) {
	data, err := json.Marshal(loginPayload{m.ID, m.State, m.Nonce, m.Verifier, m.CreatedAt})
	if err != nil {
		return services.Envelope{}, ErrCredentials
	}
	defer clear(data)
	return c.Seal(ctx, b, data)
}
func (c *Credentials) OpenLogin(ctx context.Context, b services.CredentialContext, e services.Envelope) (services.LoginMaterial, error) {
	data, err := c.Open(ctx, b, e)
	if err != nil {
		return services.LoginMaterial{}, ErrCredentials
	}
	defer clear(data)
	var m loginPayload
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(&struct{}{}) != io.EOF || m.ID != b.Session {
		return services.LoginMaterial{}, ErrCredentials
	}
	return services.LoginMaterial{ID: m.ID, State: m.State, Nonce: m.Nonce, Verifier: m.Verifier, CreatedAt: m.Created}, nil
}
