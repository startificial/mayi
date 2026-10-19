// Package memory provides a single-process reference store. Restart invalidates
// all sessions. Multi-replica deployments must supply a durable serialized lease.
package memory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/startificial/mayi/examples/bff/services"
	"strings"
	"sync"
	"time"
)

var _ services.SessionStore = (*Sessions)(nil)
var _ services.SessionLease = (*lease)(nil)

type entry struct {
	record  services.Session
	invalid bool
	gate    chan struct{}
}
type Sessions struct {
	mu      sync.Mutex
	records map[string]*entry
}
type lease struct {
	value      *entry
	refreshing bool
}

func New() *Sessions           { return &Sessions{records: map[string]*entry{}} }
func digest(raw string) string { sum := sha256.Sum256([]byte(raw)); return hex.EncodeToString(sum[:]) }
func clone(r services.Session) services.Session {
	r.Credentials.Ciphertext = append([]byte(nil), r.Credentials.Ciphertext...)
	return r
}
func (s *Sessions) Create(ctx context.Context, r services.Session) (string, error) {
	if ctx.Err() != nil || r.Generation != 1 || r.ID == "" || len(r.ID) > 128 || strings.ContainsAny(r.ID, ". ;\r\n\x00") || len(r.Credentials.Ciphertext) == 0 || !r.ExpiresAt.After(time.Now()) {
		return "", services.ErrSession
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", services.ErrSession
	}
	raw := r.ID + "." + base64.RawURLEncoding.EncodeToString(entropy[:])
	hash := digest(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Bound the reference store; expired entries can be replaced without retaining
	// bearer cookies or plaintext tokens. Never evict a live lease.
	for key, e := range s.records {
		if !e.record.ExpiresAt.After(time.Now()) {
			delete(s.records, key)
		}
	}
	for _, e := range s.records {
		if e.record.ID == r.ID {
			return "", services.ErrSession
		}
	}
	if len(s.records) >= 10000 || s.records[hash] != nil {
		return "", services.ErrSession
	}
	s.records[hash] = &entry{record: clone(r), gate: make(chan struct{}, 1)}
	return raw, nil
}
func (s *Sessions) WithSession(ctx context.Context, raw string, fn func(services.SessionLease) error) error {
	id, secret, ok := strings.Cut(raw, ".")
	if !ok || id == "" || len(id) > 128 || len(secret) != 43 || fn == nil {
		return services.ErrSession
	}
	s.mu.Lock()
	e := s.records[digest(raw)]
	s.mu.Unlock()
	if e == nil {
		return services.ErrSession
	}
	select {
	case e.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-e.gate }()
	if e.record.ID != id || e.invalid || !e.record.ExpiresAt.After(time.Now()) {
		return services.ErrSession
	}
	return fn(&lease{value: e})
}
func (l *lease) Session() services.Session { return clone(l.value.record) }
func (l *lease) BeginRefresh(ctx context.Context) error {
	if ctx.Err() != nil || l.value.invalid || l.refreshing {
		return services.ErrSession
	}
	l.refreshing = true
	l.value.invalid = true
	clear(l.value.record.Credentials.Ciphertext)
	return nil
}
func (l *lease) Replace(ctx context.Context, generation uint64, envelope services.Envelope) error {
	if ctx.Err() != nil || !l.refreshing || generation != l.value.record.Generation+1 || len(envelope.Ciphertext) == 0 {
		return services.ErrSession
	}
	l.value.record.Generation = generation
	envelope.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	l.value.record.Credentials = envelope
	l.value.invalid = false
	l.refreshing = false
	return nil
}
func (l *lease) Invalidate(context.Context) error {
	l.value.invalid = true
	clear(l.value.record.Credentials.Ciphertext)
	return nil
}
