package tokens

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	"strings"
	"testing"
	"time"
)

type proofClock struct{ now time.Time }

func (c proofClock) Now() time.Time { return c.now }

type proofVerifier struct {
	t    *testing.T
	mode string
	now  time.Time
}

func (v proofVerifier) VerifyProof(context.Context, ProofRequest, time.Time) (VerifiedProof, error) {
	if v.mode == "signature" {
		return VerifiedProof{}, ErrInvalidCredential
	}
	thumb := strings.Repeat("a", 43)
	if v.mode == "wrong key" {
		thumb = strings.Repeat("b", 43)
	}
	nonce := "v1." + strings.Repeat("A", 43)
	if v.mode == "missing nonce" {
		nonce = ""
	}
	return VerifiedProof{Thumbprint: thumb, ID: "unique-proof-id-12345", Nonce: nonce, ExpiresAt: v.now.Add(time.Minute)}, nil
}

type nonceMaterial struct {
	t    *testing.T
	mode string
}

func (m nonceMaterial) NewNonce(context.Context, grants.Scope) (string, string, error) {
	if m.mode == "signature" || m.mode == "wrong key" {
		m.t.Fatal("denied proof generated nonce")
	}
	return "v1." + strings.Repeat("B", 43), strings.Repeat("b", 64), nil
}
func (m nonceMaterial) HashNonce(_ grants.Scope, raw string) (string, error) {
	if raw == "" {
		return "", ErrInvalidCredential
	}
	return strings.Repeat("a", 64), nil
}

type proofState struct {
	t                    *testing.T
	mode                 string
	scope                grants.Scope
	now                  time.Time
	replayed, remembered bool
}

func (s *proofState) ValidProofNonce(_ context.Context, scope grants.Scope, purpose, target, thumb, hash string) (bool, error) {
	if s.mode == "signature" || s.mode == "wrong key" {
		s.t.Fatal("invalid proof loaded nonce state")
	}
	if scope != s.scope || purpose != "token" || target != "https://auth.example/t/a/token" || len(thumb) != 43 || len(hash) != 64 {
		s.t.Fatal("nonce tuple lost")
	}
	if s.mode == "nonce unavailable" {
		return false, ErrUnavailable
	}
	return s.mode != "expired nonce", nil
}
func (s *proofState) RememberProofNonce(_ context.Context, scope grants.Scope, purpose, target, thumb, hash string, expiry time.Time) error {
	s.remembered = true
	if scope != s.scope || purpose != "token" || target != "https://auth.example/t/a/token" || len(hash) != 64 || !expiry.Equal(s.now.Add(time.Minute)) {
		s.t.Fatal("nonce tuple or lifetime lost")
	}
	if s.mode == "write unavailable" {
		return ErrUnavailable
	}
	return nil
}
func (s *proofState) ConsumeProof(_ context.Context, _ grants.Scope, p ProofReplay) error {
	s.replayed = true
	if p.NonceHash != strings.Repeat("a", 64) || p.Purpose != "token" || p.Target != "https://auth.example/t/a/token" {
		s.t.Fatal("replay missing nonce recheck")
	}
	if s.mode == "replay" {
		return ErrInvalidCredential
	}
	if s.mode == "replay unavailable" {
		return ErrUnavailable
	}
	return nil
}

func TestProofAdmissionFailsBeforeAuthorityAndDistinguishesUnavailableState(t *testing.T) {
	now := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	for _, mode := range []string{"valid", "signature", "wrong key", "missing nonce", "expired nonce", "nonce unavailable", "replay", "replay unavailable", "write unavailable"} {
		t.Run(mode, func(t *testing.T) {
			state := &proofState{t: t, mode: mode, scope: scope, now: now}
			verifierMode := mode
			if mode == "write unavailable" {
				verifierMode = "missing nonce"
			}
			svc, err := NewProofs(proofVerifier{t, verifierMode, now}, state, state, nonceMaterial{t, mode}, proofClock{now})
			if err != nil {
				t.Fatal(err)
			}
			thumb, err := svc.Verify(context.Background(), scope, ProofRequest{JWT: "signed-proof", Method: "POST", URL: scope.Issuer + "/token", ExpectedThumbprint: strings.Repeat("a", 43)})
			var challenge *NonceChallenge
			switch mode {
			case "valid":
				if err != nil || thumb == "" || !state.replayed {
					t.Fatal("valid admission failed", err)
				}
			case "signature", "wrong key", "replay":
				if !errors.Is(err, ErrInvalidProof) || thumb != "" {
					t.Fatal("invalid proof accepted", err)
				}
			case "missing nonce", "expired nonce":
				if !errors.As(err, &challenge) || thumb != "" || state.replayed || !state.remembered {
					t.Fatal("nonce challenge changed authority", err)
				}
			default:
				if !errors.Is(err, ErrUnavailable) || thumb != "" {
					t.Fatal("dependency failure disguised as bad proof", err)
				}
			}
		})
	}
}
