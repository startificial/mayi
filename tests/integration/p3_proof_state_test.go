package integration_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
)

func TestP3ProofNoncesAreSharedScopedAndFailClosed(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	key := proofKey(t)
	hash, err := cryptoadapter.NewSecretHasher([]cryptoadapter.HashKey{{Version: 1, Key: []byte(strings.Repeat("k", 32)), Active: true}})
	if err != nil {
		t.Fatal(err)
	}
	source, err := cryptoadapter.NewProofNonces(e.scope, hash)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := postgres.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	first, err := tokens.NewProofs(cryptoadapter.NewDPoP(), e.store, e.store, source, clock{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := tokens.NewProofs(cryptoadapter.NewDPoP(), replica, replica, source, clock{})
	if err != nil {
		t.Fatal(err)
	}
	request := tokens.ProofRequest{JWT: proof(t, key, map[string]any{"nonce": ""}), Method: "POST", URL: e.scope.Issuer + "/token"}
	_, err = first.Verify(ctx, e.scope, request)
	var challenge *tokens.NonceChallenge
	if !errors.As(err, &challenge) {
		t.Fatal("initial nonce challenge", err)
	}
	request.JWT = proof(t, key, map[string]any{"nonce": challenge.Nonce})
	// A second service instance accepts the first instance's nonce; one replay wins globally.
	wins := make(chan bool, 2)
	var group sync.WaitGroup
	for i := range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			svc := first
			if i == 1 {
				svc = second
			}
			thumb, _ := svc.Verify(ctx, e.scope, request)
			wins <- thumb != ""
		}()
	}
	group.Wait()
	close(wins)
	accepted := 0
	for win := range wins {
		if win {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("replicas admitted replay", accepted)
	}
	foreign := grants.Scope{TenantID: "b", Issuer: "https://auth.example/t/b"}
	var visible bool
	digest, err := source.HashNonce(e.scope, challenge.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	visible, err = e.store.ValidProofNonce(ctx, foreign, "token", request.URL, thumbprint(t, key), digest)
	if err != nil || visible {
		t.Fatal("foreign tenant nonce visible", err)
	}
	for _, test := range []struct{ purpose, target, thumb string }{{"resource", request.URL, thumbprint(t, key)}, {"token", "https://auth.example/t/a/other", thumbprint(t, key)}, {"token", request.URL, thumbprint(t, proofKey(t))}} {
		valid, err := e.store.ValidProofNonce(ctx, e.scope, test.purpose, test.target, test.thumb, digest)
		if err != nil || valid {
			t.Fatal("nonce context substituted", err)
		}
	}
	// A nonce validated before expiry cannot be consumed after expiry.
	valid, err := e.store.ValidProofNonce(ctx, e.scope, "token", request.URL, thumbprint(t, key), digest)
	if err != nil || !valid {
		t.Fatal(err)
	}
	e.exec(t, `UPDATE mayi.proof_nonces SET expires_at=clock_timestamp()-interval '1 second'`)
	rawProof, err := cryptoadapter.NewDPoP().VerifyProof(ctx, tokens.ProofRequest{JWT: proof(t, key, map[string]any{"nonce": challenge.Nonce, "jti": "expiry-proof-123456789"}), Method: "POST", URL: request.URL}, clock{}.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.ConsumeProof(ctx, e.scope, tokens.ProofReplay{Thumbprint: rawProof.Thumbprint, ID: rawProof.ID, ExpiresAt: rawProof.ExpiresAt, NonceHash: digest, Purpose: "token", Target: request.URL}); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("nonce expiry race accepted", err)
	}
	// Nonce write failure must not return a usable nonce.
	e.exec(t, `ALTER TABLE mayi.proof_nonces RENAME TO unavailable_nonces`)
	request.JWT = proof(t, key, map[string]any{"nonce": "", "jti": "nonce-write-failure-123456"})
	if thumb, err := first.Verify(ctx, e.scope, request); thumb != "" || !errors.Is(err, tokens.ErrUnavailable) {
		t.Fatal("missing nonce state admitted or challenged", err)
	}
	e.exec(t, `ALTER TABLE mayi.unavailable_nonces RENAME TO proof_nonces`)
	_, err = first.Verify(ctx, e.scope, request)
	if !errors.As(err, &challenge) {
		t.Fatal(err)
	}
	request.JWT = proof(t, key, map[string]any{"nonce": challenge.Nonce, "jti": "replay-state-failure-123456"})
	e.exec(t, `ALTER TABLE mayi.proof_replays RENAME TO unavailable_replays`)
	if thumb, err := second.Verify(ctx, e.scope, request); thumb != "" || !errors.Is(err, tokens.ErrUnavailable) {
		t.Fatal("missing replay state admitted proof", err)
	}
}
