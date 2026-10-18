// Package authentication owns upstream identity correlation and local sessions.
package authentication

import (
	"context"
	"errors"
	"time"

	"github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	"github.com/startificial/mayi/internal/domain/resources"
)

var ErrDenied = errors.New("authentication denied")
var ErrUnavailable = errors.New("authentication unavailable")

type Service struct {
	store        Store
	clock        Clock
	secrets      Secrets
	provider     Provider
	tenantIssuer grants.Scope
}
type Start struct {
	BrowserHash, AuthorizationHash string
	ExpiresAt                      time.Time
}
type Challenge struct {
	URL, State, Nonce, Verifier string
	CreatedAt, ExpiresAt        time.Time
}
type Callback struct {
	State, Nonce, Verifier, Code, BrowserHash, AuthorizationHash, PreviousSessionHash string
	CreatedAt, ExpiresAt                                                              time.Time
}
type Session struct {
	Handle          string
	ExpiresAt       time.Time
	LifetimeSeconds int
}

func New(store Store, clock Clock, secrets Secrets, provider Provider, tenantIssuer grants.Scope) (*Service, error) {
	if store == nil || clock == nil || secrets == nil || provider == nil || !tenantIssuer.Valid() || !resources.ValidID(provider.ID()) || !authorization.ValidHandleHash(provider.Fingerprint()) {
		return nil, ErrUnavailable
	}
	return &Service{store, clock, secrets, provider, tenantIssuer}, nil
}
func validSecret(s string) bool {
	if len(s) != 43 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func (s *Service) Start(ctx context.Context, request Start) (Challenge, error) {
	now := s.clock.Now()
	if now.IsZero() || !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(5*time.Minute)) || !authorization.ValidHandleHash(request.BrowserHash) || !authorization.ValidHandleHash(request.AuthorizationHash) {
		return Challenge{}, ErrDenied
	}
	out := Challenge{CreatedAt: now, ExpiresAt: request.ExpiresAt}
	for _, target := range []*string{&out.State, &out.Nonce, &out.Verifier} {
		v, err := s.secrets.NewSecret(ctx)
		if err != nil || !validSecret(v) {
			return Challenge{}, ErrUnavailable
		}
		*target = v
	}
	if out.State == out.Nonce || out.State == out.Verifier || out.Nonce == out.Verifier {
		return Challenge{}, ErrUnavailable
	}
	var err error
	out.URL, err = s.provider.AuthorizationURL(out.State, out.Nonce, out.Verifier)
	if err != nil {
		return Challenge{}, ErrUnavailable
	}
	l := identity.Login{TenantIssuer: s.tenantIssuer, ProviderID: s.provider.ID(), ProviderHash: s.provider.Fingerprint(), StateHash: s.secrets.Digest(out.State), NonceHash: s.secrets.Digest(out.Nonce), VerifierHash: s.secrets.Digest(out.Verifier), BrowserHash: request.BrowserHash, AuthorizationHash: request.AuthorizationHash, CreatedAt: now, ExpiresAt: request.ExpiresAt}
	if !l.Valid() {
		return Challenge{}, ErrUnavailable
	}
	if err = s.store.StartLogin(ctx, l); err != nil {
		return Challenge{}, classify(err)
	}
	return out, nil
}
func (s *Service) Complete(ctx context.Context, input Callback) (Session, error) {
	if !validSecret(input.State) || !validSecret(input.Nonce) || !validSecret(input.Verifier) || input.Code == "" || len(input.Code) > 2048 || input.PreviousSessionHash != "" && !authorization.ValidHandleHash(input.PreviousSessionHash) {
		return Session{}, ErrDenied
	}
	for _, c := range input.Code {
		if c < 0x21 || c > 0x7e {
			return Session{}, ErrDenied
		}
	}
	l := identity.Login{TenantIssuer: s.tenantIssuer, ProviderID: s.provider.ID(), ProviderHash: s.provider.Fingerprint(), StateHash: s.secrets.Digest(input.State), NonceHash: s.secrets.Digest(input.Nonce), VerifierHash: s.secrets.Digest(input.Verifier), BrowserHash: input.BrowserHash, AuthorizationHash: input.AuthorizationHash, CreatedAt: input.CreatedAt, ExpiresAt: input.ExpiresAt}
	if !l.ActiveAt(s.clock.Now()) {
		return Session{}, ErrDenied
	}
	// Claim commits before the external exchange. Even a failed exchange consumes
	// this attempt; retry starts a new workflow, rather than replaying a code.
	if err := s.store.ClaimLogin(ctx, l, s.clock.Now()); err != nil {
		return Session{}, classify(err)
	}
	evidence, err := s.provider.Authenticate(ctx, input.Code, input.Nonce, input.Verifier, s.clock.Now())
	if err != nil {
		return Session{}, classify(err)
	}
	now := s.clock.Now()
	if !l.ActiveAt(now) || !evidence.ValidAt(now) {
		return Session{}, ErrDenied
	}
	handle, err := s.secrets.NewSecret(ctx)
	if err != nil || !validSecret(handle) {
		return Session{}, ErrUnavailable
	}
	if err := s.store.CompleteLogin(ctx, l, evidence, s.secrets.Digest(handle), input.PreviousSessionHash, now); err != nil {
		return Session{}, classify(err)
	}
	return Session{Handle: handle, ExpiresAt: now.Add(identity.SessionLifetime), LifetimeSeconds: int(identity.SessionLifetime / time.Second)}, nil
}
func (s *Service) End(ctx context.Context, sessionHash, browserHash string) error {
	if !authorization.ValidHandleHash(sessionHash) || !authorization.ValidHandleHash(browserHash) {
		return ErrDenied
	}
	return classify(s.store.EndSession(ctx, s.tenantIssuer, sessionHash, browserHash, s.clock.Now()))
}
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrDenied) {
		return ErrDenied
	}
	return ErrUnavailable
}
