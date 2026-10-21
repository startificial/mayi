// These fixtures exercise the service's transaction contract using a serialized,
// rollback-capable in-memory double. They are not PostgreSQL or KMS integration evidence.
package contract_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/app"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/authentication"
	"github.com/startificial/mayi/internal/services/tokens"
)

const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type policy struct {
	denied  bool
	calls   int
	version uint64
}

func (p *policy) AuthorizeRedemption(context.Context, tokens.Caller, string) (uint64, error) {
	p.calls++
	if p.denied {
		return 0, errors.New("denied")
	}
	return p.version, nil
}

type material struct {
	n    int
	fail bool
}

func (m *material) NewMaterial(context.Context) (tokens.Material, error) {
	if m.fail {
		return tokens.Material{}, errors.New("entropy failed")
	}
	m.n++
	return tokens.Material{ID: fmt.Sprintf("issuance-%d", m.n), RefreshSecret: fmt.Sprintf("plaintext-%d", m.n), RefreshHash: fmt.Sprintf("hash-%d", m.n)}, nil
}

type signer struct {
	fail  bool
	calls int
}

func (s *signer) SignAccessToken(_ context.Context, c domain.AccessClaims) (string, error) {
	s.calls++
	if s.fail {
		return "", errors.New("KMS unavailable; internal details must not escape")
	}
	return "fixture-signature:" + c.ID, nil
}

type memoryState struct {
	credentialObjects map[string]grants.ObjectCeiling
	credentials       map[string]tokens.Credential
	grant             tokens.GrantState
	issuances         []tokens.Issuance
	audit             []string
	revokedCodes      map[string]bool
}

func (s memoryState) clone() memoryState {
	copy := s
	copy.credentialObjects = make(map[string]grants.ObjectCeiling, len(s.credentialObjects))
	for key, value := range s.credentialObjects {
		copy.credentialObjects[key] = value
	}
	copy.revokedCodes = make(map[string]bool, len(s.revokedCodes))
	for k, v := range s.revokedCodes {
		copy.revokedCodes[k] = v
	}
	copy.credentials = make(map[string]tokens.Credential, len(s.credentials))
	for k, v := range s.credentials {
		v.CeilingScopes = slices.Clone(v.CeilingScopes)
		copy.credentials[k] = v
	}
	copy.grant.CurrentScopes = slices.Clone(s.grant.CurrentScopes)
	copy.issuances = slices.Clone(s.issuances)
	copy.audit = slices.Clone(s.audit)
	return copy
}

type store struct {
	mu                                sync.Mutex
	state                             memoryState
	runs, grantReads                  int
	commitFail, writeFail, revokeFail bool
	budgetDeniedDimension             string
	afterCallback                     func()
}
type transaction struct {
	store *store
	scope grants.Scope
	state *memoryState
}

func (s *store) Run(ctx context.Context, scope grants.Scope, fn func(tokens.Transaction) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs++
	if err := ctx.Err(); err != nil {
		return err
	}
	copy := s.state.clone()
	tx := &transaction{store: s, scope: scope, state: &copy}
	if err := fn(tx); err != nil {
		return err
	}
	if s.afterCallback != nil {
		s.afterCallback()
	}
	if s.commitFail {
		return errors.New("commit failed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.state = copy
	return nil
}
func (t *transaction) Credential(_ context.Context, hash string) (tokens.Credential, error) {
	c, ok := t.state.credentials[hash]
	if !ok || c.Scope != t.scope {
		return tokens.Credential{}, tokens.ErrInvalidCredential
	}
	return c, nil
}
func (t *transaction) CredentialObjects(_ context.Context, c tokens.Credential) (grants.ObjectCeiling, error) {
	objects, ok := t.state.credentialObjects[c.Hash]
	if !ok || c.Scope != t.scope {
		return grants.ObjectCeiling{}, tokens.ErrInvalidCredential
	}
	return objects, nil
}

func (t *transaction) GrantRevision(_ context.Context, id string, revision uint64) (tokens.GrantState, error) {
	t.store.grantReads++
	spec := t.state.grant.Revision.Snapshot()
	if spec.Scope != t.scope || spec.GrantID != id || spec.Number != revision {
		return tokens.GrantState{}, tokens.ErrInvalidCredential
	}
	return t.state.grant, nil
}
func (t *transaction) RevokeReplay(_ context.Context, c tokens.Credential) error {
	if t.store.revokeFail {
		return errors.New("revoke failed")
	}
	// Track code lineage separately: code replay must not revoke unrelated grant revisions.
	if c.Kind == tokens.AuthorizationCode {
		t.state.revokedCodes[c.Hash] = true
	} else {
		t.state.grant.Revoked = true
	}
	t.state.audit = append(t.state.audit, "replay:"+c.Kind)
	return nil
}
func (t *transaction) CommitIssuance(_ context.Context, c tokens.Credential, i tokens.Issuance) error {
	c.Consumed = true
	t.state.credentials[c.Hash] = c
	t.state.issuances = append(t.state.issuances, i)
	if i.RefreshHash != "" {
		next := c
		next.Hash = i.RefreshHash
		next.Consumed = false
		next.CeilingScopes = slices.Clone(i.Claims.Scopes)
		if !i.Claims.ObjectCeiling.IsZero() {
			t.state.credentialObjects[next.Hash] = i.Claims.ObjectCeiling
		}
		t.state.credentials[next.Hash] = next
	}
	if t.store.writeFail {
		return errors.New("audit write failed")
	}
	t.state.audit = append(t.state.audit, "issued:"+i.Claims.ID)
	return nil
}

type fixture struct {
	service  *tokens.Service
	policy   *policy
	store    *store
	signer   *signer
	material *material
	cmd      tokens.Command
	now      time.Time
}

func newFixture(t *testing.T, kind string) *fixture {
	t.Helper()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	scope := grants.Scope{TenantID: "tenant-a", Issuer: "https://auth.example/t/a"}
	objects, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: scope, Resource: "https://api.example/a", Details: []grants.ObjectDetail{{Type: "https://api.example/types/fixture/v1", Identifier: "123", Actions: []string{"read", "write"}}}})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := resources.NewObjectProfile(resources.ObjectProfileSpec{Scope: scope, Resource: "https://api.example/a", Type: "https://api.example/types/fixture/v1", Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read items"}, {Name: "write", Description: "Write items"}}})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := grants.NewRevision(grants.RevisionSpec{ObjectCeiling: objects, Scope: scope, GrantID: "grant-1", Number: 7, ClientID: "client:web", Subject: "user:alice", PrincipalType: "user", Resource: "https://api.example/a", Scopes: []string{"read", "write"}, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	credential := tokens.Credential{ObjectBound: true, Scope: scope, Hash: "original-hash", Kind: kind, ClientID: "client:web", Resource: "https://api.example/a", GrantID: "grant-1", Revision: 7, RedirectURI: "https://client.example/callback", IssuedAt: now, CeilingScopes: []string{"read", "write"}, PKCEChallenge: challenge, BindingThumbprint: "dpop-key", ExpiresAt: now.Add(60 * time.Second), FamilyDeadline: now.Add(2 * time.Minute)}
	state := memoryState{credentialObjects: map[string]grants.ObjectCeiling{credential.Hash: objects}, credentials: map[string]tokens.Credential{credential.Hash: credential}, grant: tokens.GrantState{ObjectProfiles: []resources.ObjectProfile{profile}, CurrentObjectCeiling: objects, Revision: revision, CurrentScopes: []string{"read", "write"}, PolicyVersion: 1, AuthorizationDeadline: now.Add(time.Hour)}}
	f := &fixture{policy: &policy{version: 1}, store: &store{state: state}, signer: &signer{}, material: &material{}, now: now, cmd: tokens.Command{Caller: tokens.Caller{Scope: scope, ClientID: credential.ClientID, BindingThumbprint: credential.BindingThumbprint}, Kind: kind, CredentialHash: credential.Hash, Resource: credential.Resource, Verifier: verifier, Scopes: []string{"read"}}}
	f.service, err = app.NewIssuance(f.policy, fixedClock{now}, f.signer, f.material, f.store, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func assertEmpty(t *testing.T, r tokens.Result, err error, want error) {
	t.Helper()
	if !errors.Is(err, want) || r.AccessToken != "" || r.RefreshToken != "" || r.Claims.ID != "" {
		t.Fatalf("expected empty %v response, got %+v %v", want, r, err)
	}
}

func TestRedemptionBindsHistoricalRevisionAndResource(t *testing.T) {
	for _, kind := range []string{tokens.AuthorizationCode, tokens.RefreshToken} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, kind)
			result, err := f.service.Redeem(context.Background(), f.cmd)
			if err != nil {
				t.Fatal(err)
			}
			if result.AccessToken == "" || result.Claims.Revision != 7 || result.Claims.GrantID != "grant-1" || !slices.Equal(result.Claims.Scopes, []string{"read"}) || result.Claims.Scope != f.cmd.Caller.Scope || result.Claims.Resource != f.cmd.Resource || result.Claims.BindingThumbprint != "dpop-key" {
				t.Fatalf("wrong issuance: %+v", result)
			}
			if len(f.store.state.audit) != 1 || !f.store.state.credentials[f.cmd.CredentialHash].Consumed {
				t.Fatal("issuance not atomically recorded")
			}
			if kind == tokens.RefreshToken {
				if result.RefreshToken == "" || !result.Claims.ExpiresAt.Equal(f.now.Add(2*time.Minute)) || f.store.state.issuances[0].RefreshHash == result.RefreshToken {
					t.Fatal("refresh boundary/lifetime violated")
				}
			}
		})
	}
}

func TestAuthorizationDenialNeverLoadsProtectedData(t *testing.T) {
	f := newFixture(t, tokens.AuthorizationCode)
	f.policy.denied = true
	r, err := f.service.Redeem(context.Background(), f.cmd)
	assertEmpty(t, r, err, tokens.ErrInvalidCredential)
	if f.store.runs != 0 || f.signer.calls != 0 {
		t.Fatal("unauthorized request reached persistence/signing")
	}
}

func TestForeignTenantAndProofCannotLoadGrantOrTriggerRevocation(t *testing.T) {
	cases := map[string]func(*fixture){
		"foreign tenant":   func(f *fixture) { f.cmd.Caller.Scope.TenantID = "tenant-b" },
		"foreign issuer":   func(f *fixture) { f.cmd.Caller.Scope.Issuer = "https://other.example/t/a" },
		"foreign client":   func(f *fixture) { f.cmd.Caller.ClientID = "client:other" },
		"foreign resource": func(f *fixture) { f.cmd.Resource = "https://api.example/b" },
		"wrong key":        func(f *fixture) { f.cmd.Caller.BindingThumbprint = "other-key" },
		"missing key":      func(f *fixture) { f.cmd.Caller.BindingThumbprint = "" },
		"wrong redirect":   func(f *fixture) { f.cmd.RedirectURI = "https://attacker.example/callback" },
		"wrong verifier":   func(f *fixture) { f.cmd.Verifier = "wrong" },
		"wrong purpose":    func(f *fixture) { f.cmd.Kind = tokens.RefreshToken },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tokens.AuthorizationCode)
			c := f.store.state.credentials[f.cmd.CredentialHash]
			c.Consumed = true
			f.store.state.credentials[c.Hash] = c
			change(f)
			r, err := f.service.Redeem(context.Background(), f.cmd)
			assertEmpty(t, r, err, tokens.ErrInvalidCredential)
			if f.store.grantReads != 0 || f.signer.calls != 0 || len(f.store.state.audit) != 0 || f.store.state.grant.Revoked {
				t.Fatal("unverified caller loaded grant or revoked lineage")
			}
		})
	}
}

func TestPolicyRevocationExpiryAndPermissionChangesFailClosed(t *testing.T) {
	cases := map[string]func(*fixture){
		"revoked":            func(f *fixture) { f.store.state.grant.Revoked = true },
		"policy changed":     func(f *fixture) { f.store.state.grant.PolicyVersion = 2 },
		"permission removed": func(f *fixture) { f.store.state.grant.CurrentScopes = []string{"write"} },
		"scope expanded":     func(f *fixture) { f.cmd.Scopes = []string{"admin"} },
		"expired credential": func(f *fixture) {
			c := f.store.state.credentials[f.cmd.CredentialHash]
			c.ExpiresAt = f.now
			f.store.state.credentials[c.Hash] = c
		},
		"expired family": func(f *fixture) {
			c := f.store.state.credentials[f.cmd.CredentialHash]
			c.FamilyDeadline = f.now
			f.store.state.credentials[c.Hash] = c
		},
		"unknown credential": func(f *fixture) { f.cmd.CredentialHash = "missing" },
		"invalid scopes":     func(f *fixture) { f.cmd.Scopes = []string{"read write"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tokens.RefreshToken)
			change(f)
			r, err := f.service.Redeem(context.Background(), f.cmd)
			assertEmpty(t, r, err, tokens.ErrInvalidCredential)
			if f.signer.calls != 0 || len(f.store.state.issuances) != 0 {
				t.Fatal("invalid authority reached signing/issuance")
			}
		})
	}
}

func TestHistoricalRevisionLookupNeverUsesLatestConsent(t *testing.T) {
	f := newFixture(t, tokens.AuthorizationCode)
	spec := f.store.state.grant.Revision.Snapshot()
	spec.Number = 8
	spec.Scopes = append(spec.Scopes, "admin")
	revision, err := grants.NewRevision(spec)
	if err != nil {
		t.Fatal(err)
	}
	f.store.state.grant.Revision = revision
	r, err := f.service.Redeem(context.Background(), f.cmd)
	assertEmpty(t, r, err, tokens.ErrInvalidCredential)
	if f.signer.calls != 0 {
		t.Fatal("latest revision substituted for approved revision")
	}
}

func TestFailuresRollbackAndNeverReturnCredentials(t *testing.T) {
	cases := map[string]func(*fixture){
		"signer":  func(f *fixture) { f.signer.fail = true },
		"entropy": func(f *fixture) { f.material.fail = true },
		"audit":   func(f *fixture) { f.store.writeFail = true },
		"commit":  func(f *fixture) { f.store.commitFail = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tokens.RefreshToken)
			change(f)
			r, err := f.service.Redeem(context.Background(), f.cmd)
			assertEmpty(t, r, err, tokens.ErrUnavailable)
			if f.store.state.credentials[f.cmd.CredentialHash].Consumed || len(f.store.state.issuances) != 0 || len(f.store.state.audit) != 0 {
				t.Fatal("failed transaction leaked state")
			}
		})
	}
}

func TestNoCredentialEscapesBeforeCommit(t *testing.T) {
	f := newFixture(t, tokens.AuthorizationCode)
	entered := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})
	f.store.afterCallback = func() { close(entered); <-release }
	go func() { defer close(returned); _, _ = f.service.Redeem(context.Background(), f.cmd) }()
	<-entered
	select {
	case <-returned:
		t.Fatal("response returned before durable commit")
	default:
	}
	close(release)
	<-returned
}

func TestAuthenticatedReplayCommitsRevocationAndDisablesSuccessor(t *testing.T) {
	for _, kind := range []string{tokens.AuthorizationCode, tokens.RefreshToken} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, kind)
			first, err := f.service.Redeem(context.Background(), f.cmd)
			if err != nil {
				t.Fatal(err)
			}
			r, err := f.service.Redeem(context.Background(), f.cmd)
			assertEmpty(t, r, err, tokens.ErrInvalidCredential)
			if !f.replayRevoked() || len(f.store.state.audit) != 2 || f.signer.calls != 1 {
				t.Fatal("replay revocation was rolled back or duplicate token signed")
			}
			if kind == tokens.RefreshToken {
				f.cmd.CredentialHash = f.store.state.issuances[0].RefreshHash
				r, err = f.service.Redeem(context.Background(), f.cmd)
				assertEmpty(t, r, err, tokens.ErrInvalidCredential)
				if first.RefreshToken == "" {
					t.Fatal("missing first successor")
				}
			}
		})
	}
}

func TestConcurrentRedemptionHasOneWinnerAndReplayRevokes(t *testing.T) {
	// Separate policies avoid sharing the test counter; the store serializes the
	// real critical section. Both services share the same signer/material source.
	for _, kind := range []string{tokens.AuthorizationCode, tokens.RefreshToken} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, kind)
			second, err := app.NewIssuance(&policy{version: 1}, fixedClock{f.now}, f.signer, f.material, f.store, 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			done := make(chan error, 2)
			for _, s := range []*tokens.Service{f.service, second} {
				go func(s *tokens.Service) { <-start; _, err := s.Redeem(context.Background(), f.cmd); done <- err }(s)
			}
			close(start)
			a, b := <-done, <-done
			if (a == nil) == (b == nil) || a != nil && !errors.Is(a, tokens.ErrInvalidCredential) || b != nil && !errors.Is(b, tokens.ErrInvalidCredential) {
				t.Fatalf("expected one winner: %v %v", a, b)
			}
			if len(f.store.state.issuances) != 1 || !f.replayRevoked() || len(f.store.state.audit) != 2 {
				t.Fatal("race violated atomicity/replay contract")
			}
		})
	}
}

func TestReplayRevocationFailureFailsClosed(t *testing.T) {
	f := newFixture(t, tokens.RefreshToken)
	if _, err := f.service.Redeem(context.Background(), f.cmd); err != nil {
		t.Fatal(err)
	}
	f.store.revokeFail = true
	r, err := f.service.Redeem(context.Background(), f.cmd)
	assertEmpty(t, r, err, tokens.ErrUnavailable)
	if f.store.state.grant.Revoked || len(f.store.state.audit) != 1 {
		t.Fatal("failed revoke partially committed")
	}
}

func TestRefreshSuccessorCannotRegainScopes(t *testing.T) {
	f := newFixture(t, tokens.RefreshToken)
	if _, err := f.service.Redeem(context.Background(), f.cmd); err != nil {
		t.Fatal(err)
	}
	f.cmd.CredentialHash = f.store.state.issuances[0].RefreshHash
	f.cmd.Scopes = []string{"write"}
	r, err := f.service.Redeem(context.Background(), f.cmd)
	assertEmpty(t, r, err, tokens.ErrInvalidCredential)
	if f.signer.calls != 1 {
		t.Fatal("rotated credential regained parent scopes")
	}
	f.cmd.Scopes = nil
	r, err = f.service.Redeem(context.Background(), f.cmd)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Claims.Scopes, []string{"read"}) {
		t.Fatal("default refresh expanded predecessor ceiling")
	}
}

func TestCodeLifetimeCannotExceedSixtySeconds(t *testing.T) {
	f := newFixture(t, tokens.AuthorizationCode)
	c := f.store.state.credentials[f.cmd.CredentialHash]
	c.ExpiresAt = f.now.Add(61 * time.Second)
	f.store.state.credentials[c.Hash] = c
	r, err := f.service.Redeem(context.Background(), f.cmd)
	assertEmpty(t, r, err, tokens.ErrInvalidCredential)
	if f.store.grantReads != 0 {
		t.Fatal("invalid code lifetime loaded grant")
	}
}

func TestOptionalRedirectStillMatchesWhenPresent(t *testing.T) {
	f := newFixture(t, tokens.AuthorizationCode)
	f.cmd.RedirectURI = "https://client.example/callback"
	if _, err := f.service.Redeem(context.Background(), f.cmd); err != nil {
		t.Fatal(err)
	}
}

func TestCancellationBeforeCommitReturnsNoCredentials(t *testing.T) {
	f := newFixture(t, tokens.AuthorizationCode)
	ctx, cancel := context.WithCancel(context.Background())
	f.store.afterCallback = cancel
	r, err := f.service.Redeem(ctx, f.cmd)
	assertEmpty(t, r, err, tokens.ErrUnavailable)
	if f.store.state.credentials[f.cmd.CredentialHash].Consumed || len(f.store.state.issuances) != 0 {
		t.Fatal("cancelled commit persisted state")
	}
}

func (f *fixture) replayRevoked() bool {
	if f.cmd.Kind == tokens.AuthorizationCode {
		return f.store.state.revokedCodes[f.cmd.CredentialHash]
	}
	return f.store.state.grant.Revoked
}

func TestCodeReplayDoesNotRevokeUnrelatedCode(t *testing.T) {
	f := newFixture(t, tokens.AuthorizationCode)
	if _, err := f.service.Redeem(context.Background(), f.cmd); err != nil {
		t.Fatal(err)
	}
	_, _ = f.service.Redeem(context.Background(), f.cmd)
	if !f.replayRevoked() || f.store.state.grant.Revoked {
		t.Fatal("code replay revocation was not scoped to lineage")
	}
	another := f.store.state.credentials[f.cmd.CredentialHash]
	another.Hash = "independent-code"
	another.Consumed = false
	f.store.state.credentials[another.Hash] = another
	f.store.state.credentialObjects[another.Hash] = f.store.state.grant.Revision.Snapshot().ObjectCeiling
	f.cmd.CredentialHash = another.Hash
	if _, err := f.service.Redeem(context.Background(), f.cmd); err != nil {
		t.Fatal("unrelated code was revoked", err)
	}
}

type sequenceClock struct {
	values []time.Time
	next   int
}

func (c *sequenceClock) Now() time.Time { value := c.values[c.next]; c.next++; return value }

func TestSlowOrBrokenSignerClockCannotCommitExpiredCredentials(t *testing.T) {
	for name, elapsed := range map[string]time.Duration{"credential expired": 61 * time.Second, "token expired": 6 * time.Minute, "clock reversed": -time.Second} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tokens.AuthorizationCode)
			clock := &sequenceClock{values: []time.Time{f.now, f.now.Add(elapsed)}}
			service, err := app.NewIssuance(f.policy, clock, f.signer, f.material, f.store, 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			r, err := service.Redeem(context.Background(), f.cmd)
			want := tokens.ErrUnavailable
			if name == "credential expired" {
				want = tokens.ErrInvalidCredential
			}
			assertEmpty(t, r, err, want)
			if f.store.state.credentials[f.cmd.CredentialHash].Consumed || len(f.store.state.issuances) != 0 {
				t.Fatal("expired issuance committed")
			}
		})
	}
}

func (*material) DigestAccessToken(raw string) string { return "digest:" + raw }

func (s *store) ConsumeBudget(_ context.Context, _ grants.Scope, b authentication.Budget) (bool, error) {
	return b.Dimension != s.budgetDeniedDimension, nil
}
func (t *transaction) ConsumeBudget(ctx context.Context, scope grants.Scope, b authentication.Budget) (bool, error) {
	return t.store.ConsumeBudget(ctx, scope, b)
}

func TestDirectRedemptionCannotBypassClientOrUserAdmission(t *testing.T) {
	for _, dimension := range []string{"client", "user"} {
		t.Run(dimension, func(t *testing.T) {
			f := newFixture(t, tokens.AuthorizationCode)
			f.store.budgetDeniedDimension = dimension
			result, err := f.service.Redeem(context.Background(), f.cmd)
			if !errors.Is(err, authentication.ErrLimited) || result.AccessToken != "" || f.material.n != 0 || f.signer.calls != 0 || f.store.state.credentials[f.cmd.CredentialHash].Consumed {
				t.Fatal("limited direct call issued authority", err)
			}
			if dimension == "client" && (f.store.runs != 0 || f.store.grantReads != 0) {
				t.Fatal("client admission loaded protected authority")
			}
		})
	}
}

func TestCIMDRedemptionWithoutResolutionCannotReachProtectedState(t *testing.T) {
	f := newFixture(t, tokens.AuthorizationCode)
	f.cmd.Caller.ClientID = "https://client.example/metadata.json"
	f.cmd.Caller.ClientMetadataDigest = strings.Repeat("a", 64)
	result, err := f.service.Redeem(context.Background(), f.cmd)
	assertEmpty(t, result, err, tokens.ErrInvalidCredential)
	if f.store.runs != 0 {
		t.Fatal("CIMD redemption loaded protected state without resolver")
	}
}
