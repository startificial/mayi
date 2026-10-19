package crypto_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	cryptoadapter "github.com/startificial/mayi/examples/bff/adapters/crypto"
	"github.com/startificial/mayi/examples/bff/services"
)

func TestAADRejectsContextAndEnvelopeSubstitution(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x53}, 32)
	cipher, err := cryptoadapter.New([]cryptoadapter.Key{{ID: "k1", Bytes: key, Active: true}, {ID: "k2", Bytes: key}})
	if err != nil {
		t.Fatal(err)
	}
	expected := services.CredentialContext{Tenant: "a", Issuer: "https://auth.example/t/a", Client: "web", Resource: "https://api.example", Session: "record-123", Purpose: "oauth-tokens", Generation: 1}
	secret := []byte(`{"refresh_token":"never-print-this-secret"}`)
	envelope, err := cipher.Seal(ctx, expected, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope.Ciphertext, secret) {
		t.Fatal("plaintext exposed")
	}
	opened, err := cipher.Open(ctx, expected, envelope)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatal("round trip failed", err)
	}
	tests := map[string]func(*services.CredentialContext, *services.Envelope){
		"tenant":                         func(c *services.CredentialContext, _ *services.Envelope) { c.Tenant = "b" },
		"issuer":                         func(c *services.CredentialContext, _ *services.Envelope) { c.Issuer = "https://auth.example/t/b" },
		"client":                         func(c *services.CredentialContext, _ *services.Envelope) { c.Client = "another-client" },
		"resource":                       func(c *services.CredentialContext, _ *services.Envelope) { c.Resource = "https://other-api.example" },
		"session":                        func(c *services.CredentialContext, _ *services.Envelope) { c.Session = "record-124" },
		"purpose":                        func(c *services.CredentialContext, _ *services.Envelope) { c.Purpose = "login-state" },
		"generation":                     func(c *services.CredentialContext, _ *services.Envelope) { c.Generation++ },
		"version":                        func(_ *services.CredentialContext, e *services.Envelope) { e.Version++ },
		"same material different key ID": func(_ *services.CredentialContext, e *services.Envelope) { e.KeyID = "k2" },
		"unknown key":                    func(_ *services.CredentialContext, e *services.Envelope) { e.KeyID = "missing" },
		"ciphertext":                     func(_ *services.CredentialContext, e *services.Envelope) { e.Ciphertext[len(e.Ciphertext)-1] ^= 1 },
		"nonce":                          func(_ *services.CredentialContext, e *services.Envelope) { e.Ciphertext[0] ^= 1 },
		"truncated":                      func(_ *services.CredentialContext, e *services.Envelope) { e.Ciphertext = e.Ciphertext[:10] },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			c, e := expected, envelope
			e.Ciphertext = bytes.Clone(envelope.Ciphertext)
			change(&c, &e)
			result, err := cipher.Open(ctx, c, e)
			if result != nil || !errors.Is(err, cryptoadapter.ErrCredentials) {
				t.Fatal("substitution accepted or plaintext returned")
			}
		})
	}
	second, err := cipher.Seal(ctx, expected, secret)
	if err != nil || bytes.Equal(envelope.Ciphertext, second.Ciphertext) {
		t.Fatal("nonce was reused")
	}
	rotated, err := cryptoadapter.New([]cryptoadapter.Key{{ID: "k1", Bytes: key}, {ID: "new", Bytes: bytes.Repeat([]byte{0x82}, 32), Active: true}})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := rotated.Open(ctx, expected, envelope); err != nil || !bytes.Equal(p, secret) {
		t.Fatal("retained decryption key failed")
	}
	if e, err := rotated.Seal(ctx, expected, secret); err != nil || e.KeyID != "new" {
		t.Fatal("rotation used retired key")
	}
	retired, _ := cryptoadapter.New([]cryptoadapter.Key{{ID: "new", Bytes: key, Active: true}})
	if p, err := retired.Open(ctx, expected, envelope); p != nil || err == nil {
		t.Fatal("removed key accepted")
	}
}

func TestCredentialKeysAndContextFailClosed(t *testing.T) {
	for _, keys := range [][]cryptoadapter.Key{nil, {{ID: "a", Bytes: []byte("short"), Active: true}}, {{ID: "a", Bytes: make([]byte, 32)}}, {{ID: "a", Bytes: make([]byte, 32), Active: true}, {ID: "b", Bytes: make([]byte, 32), Active: true}}} {
		if _, err := cryptoadapter.New(keys); err == nil {
			t.Fatal("invalid key ring accepted")
		}
	}
	c, _ := cryptoadapter.New([]cryptoadapter.Key{{ID: "a", Bytes: bytes.Repeat([]byte{1}, 32), Active: true}})
	if e, err := c.Seal(context.Background(), services.CredentialContext{}, []byte("secret")); err == nil || e.Ciphertext != nil {
		t.Fatal("unbound encryption accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Seal(ctx, services.CredentialContext{}, []byte("secret")); err == nil {
		t.Fatal("cancellation ignored")
	}
}
