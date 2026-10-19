package services

import (
	"context"
	"errors"
	"time"
)

var ErrSession = errors.New("application session unavailable; sign in again")
var ErrAPI = errors.New("protected API unavailable")

type Service struct {
	store   SessionStore
	cipher  CredentialCipher
	oauth   OAuthClient
	api     API
	clock   Clock
	binding CredentialContext
}

func New(store SessionStore, cipher CredentialCipher, oauth OAuthClient, api API, clock Clock, binding CredentialContext) (*Service, error) {
	if store == nil || cipher == nil || oauth == nil || api == nil || clock == nil || binding.Tenant == "" || binding.Issuer == "" || binding.Client == "" || binding.Resource == "" {
		return nil, ErrSession
	}
	return &Service{store, cipher, oauth, api, clock, binding}, nil
}
func (s *Service) bindingFor(record Session, generation uint64) CredentialContext {
	b := s.binding
	b.Session = record.ID
	b.Purpose = "oauth-tokens"
	b.Generation = generation
	return b
}
func validTokens(t Tokens, now time.Time) bool {
	return t.Access != "" && len(t.Access) <= 65536 && len(t.Refresh) <= 256 && len(t.Identity) <= 65536 && t.Type == "Bearer" && t.ExpiresAt.After(now) && !t.ExpiresAt.After(now.Add(15*time.Minute))
}

// Establish accepts only the successful exchange result from the application
// login use case, never credentials supplied by a browser request.
func (s *Service) Establish(ctx context.Context, id string, t Tokens) (string, error) {
	now := s.clock.Now()
	if !validTokens(t, now) {
		return "", ErrSession
	}
	record := Session{ID: id, Generation: 1, ExpiresAt: now.Add(time.Hour)}
	encrypted, err := s.cipher.SealTokens(ctx, s.bindingFor(record, 1), t)
	if err != nil {
		return "", ErrSession
	}
	record.Credentials = encrypted
	cookie, err := s.store.Create(ctx, record)
	if err != nil {
		return "", ErrSession
	}
	return cookie, nil
}
func (s *Service) ReadObject(ctx context.Context, cookie, id string) ([]byte, error) {
	if cookie == "" || len(cookie) > 256 || id == "" || len(id) > 256 {
		return nil, ErrSession
	}
	var result []byte
	err := s.store.WithSession(ctx, cookie, func(lease SessionLease) error {
		record := lease.Session()
		if record.Generation == 0 || !s.clock.Now().Before(record.ExpiresAt) {
			_ = lease.Invalidate(ctx)
			return ErrSession
		}
		t, err := s.cipher.OpenTokens(ctx, s.bindingFor(record, record.Generation), record.Credentials)
		if err != nil {
			_ = lease.Invalidate(ctx)
			return ErrSession
		}
		if !t.ExpiresAt.After(s.clock.Now().Add(10 * time.Second)) {
			if t.Refresh == "" {
				_ = lease.Invalidate(ctx)
				return ErrSession
			}
			if err = lease.BeginRefresh(ctx); err != nil {
				return ErrSession
			}
			// Exactly one attempt: a lost response may already have consumed the old
			// refresh token. Retrying it would trigger strict replay revocation.
			next, err := s.oauth.Refresh(ctx, t.Refresh)
			if err != nil || !validTokens(next, s.clock.Now()) || next.Refresh == "" || next.Refresh == t.Refresh {
				return ErrSession
			}
			generation := record.Generation + 1
			encrypted, err := s.cipher.SealTokens(ctx, s.bindingFor(record, generation), next)
			if err != nil {
				return ErrSession
			}
			if err = lease.Replace(ctx, generation, encrypted); err != nil {
				return ErrSession
			}
			t = next
		}
		result, err = s.api.ReadObject(ctx, t.Access, id)
		if err != nil {
			result = nil
			return ErrAPI
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (s *Service) End(ctx context.Context, cookie string) error {
	if cookie == "" || len(cookie) > 256 {
		return ErrSession
	}
	return s.store.WithSession(ctx, cookie, func(l SessionLease) error { return l.Invalidate(ctx) })
}
