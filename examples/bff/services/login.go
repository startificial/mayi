package services

import (
	"context"
	"crypto/subtle"
	"time"
)

type Login struct {
	sessions *Service
	store    SessionStore
	cipher   CredentialCipher
	client   LoginClient
	source   LoginSource
	clock    Clock
	request  AuthorizationRequest
}

func NewLogin(sessions *Service, store SessionStore, cipher CredentialCipher, client LoginClient, source LoginSource, clock Clock, request AuthorizationRequest) (*Login, error) {
	if sessions == nil || store == nil || cipher == nil || client == nil || source == nil || clock == nil || request.Type == "" || request.Identifier == "" || request.Permission == "" || len(request.Actions) == 0 {
		return nil, ErrSession
	}
	request.Actions = append([]string(nil), request.Actions...)
	return &Login{sessions, store, cipher, client, source, clock, request}, nil
}
func (l *Login) Begin(ctx context.Context) (string, string, error) {
	m, err := l.source.NewLogin(ctx)
	if err != nil {
		return "", "", ErrSession
	}
	m.CreatedAt = l.clock.Now()
	if m.ID == "" || len(m.State) != 43 || len(m.Nonce) != 43 || len(m.Verifier) != 43 {
		return "", "", ErrSession
	}
	record := Session{ID: m.ID, Generation: 1, ExpiresAt: m.CreatedAt.Add(5 * time.Minute)}
	binding := l.sessions.bindingFor(record, 1)
	binding.Purpose = "login-state"
	record.Credentials, err = l.cipher.SealLogin(ctx, binding, m)
	if err != nil {
		return "", "", ErrSession
	}
	request := l.request
	request.State = m.State
	request.Nonce = m.Nonce
	request.Verifier = m.Verifier
	destination, err := l.client.Begin(ctx, request)
	if err != nil {
		return "", "", ErrSession
	}
	cookie, err := l.store.Create(ctx, record)
	if err != nil {
		return "", "", ErrSession
	}
	return destination, cookie, nil
}
func (l *Login) Complete(ctx context.Context, cookie, state, code, issuer string) (string, error) {
	if cookie == "" || len(cookie) > 256 || len(state) != 43 || code == "" || len(code) > 256 || issuer != l.sessions.binding.Issuer {
		return "", ErrSession
	}
	var session string
	err := l.store.WithSession(ctx, cookie, func(lease SessionLease) error {
		record := lease.Session()
		binding := l.sessions.bindingFor(record, 1)
		binding.Purpose = "login-state"
		m, err := l.cipher.OpenLogin(ctx, binding, record.Credentials)
		if err != nil || subtle.ConstantTimeCompare([]byte(m.State), []byte(state)) != 1 || m.CreatedAt.After(l.clock.Now()) || !m.CreatedAt.Add(5*time.Minute).After(l.clock.Now()) {
			return ErrSession
		}
		if err = lease.BeginRefresh(ctx); err != nil {
			return ErrSession
		} // Claim once before code exchange.
		tokens, err := l.client.ExchangeIdentity(ctx, code, m)
		if err != nil {
			return ErrSession
		}
		fresh, err := l.source.NewLogin(ctx)
		if err != nil {
			return ErrSession
		}
		session, err = l.sessions.Establish(ctx, fresh.ID, tokens)
		return err
	})
	if err != nil {
		return "", ErrSession
	}
	return session, nil
}
