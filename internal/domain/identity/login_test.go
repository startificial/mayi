package identity_test

import (
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	"strings"
	"testing"
	"time"
)

func TestLoginAndAssertionBounds(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	hash := strings.Repeat("a", 64)
	l := identity.Login{TenantIssuer: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, ProviderID: "provider", ProviderHash: hash, StateHash: hash, BrowserHash: hash, AuthorizationHash: hash, NonceHash: hash, VerifierHash: hash, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if !l.ActiveAt(now) || l.ActiveAt(l.ExpiresAt) || l.ActiveAt(now.Add(-time.Second)) {
		t.Fatal("login lifetime boundary")
	}
	l.ExpiresAt = l.ExpiresAt.Add(time.Second)
	if l.Valid() {
		t.Fatal("unbounded login")
	}
	a := identity.Assertion{Issuer: "https://idp.example", Subject: "alice", AuthenticatedAt: now}
	if !a.ValidAt(now) {
		t.Fatal("fresh assertion refused")
	}
	for _, subject := range []string{"", " alice", "alice\n", strings.Repeat("a", 256)} {
		a.Subject = subject
		if a.ValidAt(now) {
			t.Fatal("invalid upstream subject accepted")
		}
	}
	a.Subject = "alice"
	a.AuthenticatedAt = now.Add(-6 * time.Minute)
	if a.ValidAt(now) {
		t.Fatal("stale authentication accepted")
	}
}

func TestAssertionMustBeFreshForItsLoginAttempt(t *testing.T) {
	start := time.Date(2026, 10, 18, 0, 0, 0, 500000000, time.UTC)
	hash := strings.Repeat("a", 64)
	login := identity.Login{TenantIssuer: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, ProviderID: "provider", ProviderHash: hash, StateHash: hash, BrowserHash: hash, AuthorizationHash: hash, NonceHash: hash, VerifierHash: hash, CreatedAt: start, ExpiresAt: start.Add(5 * time.Minute)}
	now := start.Add(4 * time.Minute)
	for _, tc := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"before attempt", start.Add(-time.Minute), false},
		{"outside skew", start.Add(-30*time.Second - time.Nanosecond), false},
		{"skew boundary", start.Add(-30 * time.Second), true},
		{"whole second", start.Truncate(time.Second), true},
		{"during attempt", start.Add(time.Minute), true},
		{"future outside skew", now.Add(31 * time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := identity.Assertion{Issuer: "https://idp.example", Subject: "alice", AuthenticatedAt: tc.at}
			if evidence.ValidFor(login, now) != tc.want {
				t.Fatal("unexpected attempt freshness decision")
			}
		})
	}
	if (identity.Assertion{Issuer: "https://idp.example", Subject: "alice", AuthenticatedAt: now}).ValidFor(login, login.ExpiresAt) {
		t.Fatal("expired attempt accepted")
	}
}
