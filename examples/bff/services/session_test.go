package services_test

import (
	"bytes"
	"context"
	"errors"
	cryptoadapter "github.com/startificial/mayi/examples/bff/adapters/crypto"
	"github.com/startificial/mayi/examples/bff/adapters/memory"
	"github.com/startificial/mayi/examples/bff/services"
	"sync"
	"testing"
	"time"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

type oauth struct {
	mu    sync.Mutex
	calls int
	fail  bool
	now   time.Time
}

func (o *oauth) Refresh(_ context.Context, old string) (services.Tokens, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	if old != "old-refresh" || o.fail {
		return services.Tokens{}, errors.New("uncertain outcome")
	}
	return services.Tokens{Access: "new-access", Refresh: "new-refresh", Type: "Bearer", ExpiresAt: o.now.Add(time.Minute)}, nil
}

type api struct{}

func (api) ReadObject(_ context.Context, token, id string) ([]byte, error) {
	if token != "new-access" || id != "123" {
		return nil, errors.New("denied")
	}
	return []byte("protected content"), nil
}
func fixture(t *testing.T) (*services.Service, *memory.Sessions, *oauth, *clock, string) {
	t.Helper()
	ctx := context.Background()
	c := &clock{now: time.Now()}
	o := &oauth{now: c.now.Add(18 * time.Second)}
	store := memory.New()
	cipher, err := cryptoadapter.New([]cryptoadapter.Key{{ID: "k1", Bytes: bytes.Repeat([]byte{7}, 32), Active: true}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := services.New(store, cipher, o, api{}, c, services.CredentialContext{Tenant: "a", Issuer: "https://auth.example/t/a", Client: "web", Resource: "https://api.example"})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := service.Establish(ctx, "record-123", services.Tokens{Access: "old-access", Refresh: "old-refresh", Type: "Bearer", ExpiresAt: c.now.Add(20 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	c.now = c.now.Add(18 * time.Second)
	return service, store, o, c, cookie
}
func TestEncryptedBFFSessionsSerializeRefresh(t *testing.T) {
	s, store, o, _, cookie := fixture(t)
	ctx := context.Background()
	if err := store.WithSession(ctx, cookie, func(l services.SessionLease) error {
		r := l.Session()
		if r.Generation != 1 || bytes.Contains(r.Credentials.Ciphertext, []byte("old-refresh")) {
			t.Fatal("session stored plaintext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			data, err := s.ReadObject(ctx, cookie, "123")
			if err != nil || string(data) != "protected content" {
				t.Error("concurrent session failed", err)
			}
		})
	}
	wg.Wait()
	if o.calls != 1 {
		t.Fatal("refresh was not serialized", o.calls)
	}
	if err := store.WithSession(ctx, cookie, func(l services.SessionLease) error {
		if l.Session().Generation != 2 {
			t.Fatal("missing encrypted revision")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if data, err := s.ReadObject(ctx, cookie, "124"); data != nil || !errors.Is(err, services.ErrAPI) {
		t.Fatal("application forwarded forbidden content")
	}
	if err := s.End(ctx, cookie); err != nil {
		t.Fatal(err)
	}
	if data, err := s.ReadObject(ctx, cookie, "123"); data != nil || err == nil {
		t.Fatal("ended session accepted")
	}
}
func TestAmbiguousRefreshInvalidatesWithoutRetry(t *testing.T) {
	s, _, o, _, cookie := fixture(t)
	o.fail = true
	for range 2 {
		if data, err := s.ReadObject(context.Background(), cookie, "123"); data != nil || !errors.Is(err, services.ErrSession) {
			t.Fatal("uncertain refresh session accepted")
		}
	}
	if o.calls != 1 {
		t.Fatal("old one-use refresh token retried")
	}
}
func TestBFFRejectsForeignCookieBeforeDecryptOrRefresh(t *testing.T) {
	s, _, o, _, _ := fixture(t)
	if data, err := s.ReadObject(context.Background(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "123"); data != nil || err == nil || o.calls != 0 {
		t.Fatal("foreign cookie reached refresh")
	}
}
