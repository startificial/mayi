package authentication_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	"github.com/startificial/mayi/internal/services/authentication"
	"strings"
	"testing"
	"time"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

type secrets struct{ n byte }

func (s *secrets) NewSecret(context.Context) (string, error) {
	s.n++
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(s.n), 32))), nil
}
func (*secrets) Digest(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

type store struct {
	login                 identity.Login
	events                *[]string
	claimErr, completeErr error
	claimed               bool
}

func (s *store) StartLogin(_ context.Context, l identity.Login) error { s.login = l; return nil }
func (s *store) ClaimLogin(_ context.Context, l identity.Login, _ time.Time) error {
	*s.events = append(*s.events, "claim")
	if s.claimErr != nil {
		return s.claimErr
	}
	if s.claimed || l != s.login {
		return authentication.ErrDenied
	}
	s.claimed = true
	return nil
}
func (s *store) CompleteLogin(context.Context, identity.Login, identity.Assertion, string, string, time.Time) error {
	*s.events = append(*s.events, "commit")
	return s.completeErr
}
func (*store) EndSession(context.Context, grants.Scope, string, string, time.Time) error { return nil }

type provider struct {
	events *[]string
	now    time.Time
	err    error
}

func (*provider) ID() string          { return "upstream" }
func (*provider) Fingerprint() string { return strings.Repeat("a", 64) }
func (*provider) AuthorizationURL(string, string, string) (string, error) {
	return "https://idp.example/authorize", nil
}
func (p *provider) Authenticate(context.Context, string, string, string, time.Time) (identity.Assertion, error) {
	*p.events = append(*p.events, "exchange")
	return identity.Assertion{Issuer: "https://idp.example", Subject: "alice", AuthenticatedAt: p.now}, p.err
}
func fixture(t *testing.T) (*authentication.Service, *store, *provider, *clock, authentication.Callback) {
	t.Helper()
	events := []string{}
	c := &clock{time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)}
	s := &store{events: &events}
	p := &provider{events: &events, now: c.now}
	svc, err := authentication.New(s, c, &secrets{}, p, grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, admissionFake{})
	if err != nil {
		t.Fatal(err)
	}
	start := authentication.Start{BrowserHash: strings.Repeat("b", 64), AuthorizationHash: strings.Repeat("c", 64), ExpiresAt: c.now.Add(5 * time.Minute)}
	ch, err := svc.Start(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	return svc, s, p, c, authentication.Callback{State: ch.State, Nonce: ch.Nonce, Verifier: ch.Verifier, Code: "upstream-code", BrowserHash: start.BrowserHash, AuthorizationHash: start.AuthorizationHash, CreatedAt: ch.CreatedAt, ExpiresAt: ch.ExpiresAt}
}
func TestLoginClaimsBeforeExchangeAndReturnsSessionAfterCommit(t *testing.T) {
	svc, s, _, _, cb := fixture(t)
	result, err := svc.Complete(context.Background(), cb)
	if err != nil || result.Handle == "" || strings.Join(*s.events, ",") != "claim,exchange,commit" {
		t.Fatal(result, err, *s.events)
	}
	if replay, err := svc.Complete(context.Background(), cb); !errors.Is(err, authentication.ErrDenied) || replay.Handle != "" {
		t.Fatal("login replay", err)
	}
}
func TestLoginDenialsNeverExchangeOrIssue(t *testing.T) {
	for _, mode := range []string{"claim denied", "foreign browser", "foreign tenant reference", "wrong nonce", "wrong verifier", "expired", "malformed code", "commit failure", "bad assertion", "exchange failure"} {
		t.Run(mode, func(t *testing.T) {
			svc, s, p, c, cb := fixture(t)
			switch mode {
			case "claim denied":
				s.claimErr = authentication.ErrDenied
			case "foreign browser":
				cb.BrowserHash = strings.Repeat("d", 64)
			case "foreign tenant reference":
				cb.AuthorizationHash = strings.Repeat("e", 64)
			case "wrong nonce":
				cb.Nonce = strings.Repeat("N", 43)
			case "wrong verifier":
				cb.Verifier = strings.Repeat("V", 43)
			case "expired":
				c.now = c.now.Add(6 * time.Minute)
			case "malformed code":
				cb.Code = "bad\ncode"
			case "commit failure":
				s.completeErr = authentication.ErrUnavailable
			case "bad assertion":
				p.now = c.now.Add(-10 * time.Minute)
			case "exchange failure":
				p.err = authentication.ErrDenied
			}
			result, err := svc.Complete(context.Background(), cb)
			if err == nil || result.Handle != "" {
				t.Fatal("denied login emitted session", result, err)
			}
			switch mode {
			case "claim denied", "foreign browser", "foreign tenant reference", "wrong nonce", "wrong verifier", "expired", "malformed code":
				for _, event := range *s.events {
					if event != "claim" {
						t.Fatal("external effect before authorization", *s.events)
					}
				}
			}
		})
	}
}

func TestFreshTokenCannotReuseAuthenticationBeforeLoginAttempt(t *testing.T) {
	svc, s, p, c, cb := fixture(t)
	// The provider can return a fresh nonce-bound token while reporting an old
	// auth_time. Recent relative to callback time is insufficient for max_age=0.
	p.now = cb.CreatedAt.Add(-time.Minute)
	c.now = cb.CreatedAt.Add(time.Minute)
	result, err := svc.Complete(context.Background(), cb)
	if !errors.Is(err, authentication.ErrDenied) || result.Handle != "" || strings.Join(*s.events, ",") != "claim,exchange" {
		t.Fatal("stale authentication issued a session", result, err, *s.events)
	}
	if _, err := svc.Complete(context.Background(), cb); !errors.Is(err, authentication.ErrDenied) || strings.Join(*s.events, ",") != "claim,exchange,claim" {
		t.Fatal("denied login was reusable", err, *s.events)
	}
}

type admissionFake struct{}

func (admissionFake) Check(context.Context, grants.Scope, string, string, string) error { return nil }

func (s *store) LoginClient(context.Context, grants.Scope, string, string, time.Time) (string, error) {
	return "web", nil
}
