package administration

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	"testing"
	"time"
)

type metadataFake struct {
	*fake
	metadataPolicy                   clients.MetadataPolicy
	state                            MetadataState
	response                         MetadataResponse
	allowed                          bool
	admitErr, fetchErr               error
	forbidState, forbidFetch         bool
	attempts, fetches, saves, purges int
	onFetch                          func()
	validators                       MetadataValidators
}

func (f *metadataFake) RunManagement(_ context.Context, _ grants.Scope, fn func(Transaction) error) error {
	if f.denyAccess {
		f.t.Fatal("metadata state accessed before admission")
	}
	if err := fn(f); err != nil {
		return err
	}
	return f.commitErr
}
func (f *metadataFake) MetadataPolicy(context.Context) (clients.MetadataPolicy, error) {
	return f.metadataPolicy, nil
}
func (f *metadataFake) SetMetadataPolicy(_ context.Context, p clients.MetadataPolicy) error {
	f.metadataPolicy = p
	return nil
}
func (f *metadataFake) MetadataState(context.Context, string) (MetadataState, error) {
	if f.forbidState {
		f.t.Fatal("cache/registration loaded before host admission")
	}
	return f.state, nil
}
func (f *metadataFake) MetadataClientCount(context.Context) (int, error) { return 0, nil }
func (f *metadataFake) SaveMetadata(_ context.Context, expected uint64, state MetadataState) error {
	if f.state.Generation != expected {
		return ErrConflict
	}
	f.saves++
	state.Client.AuthenticationVersion = 1
	f.state = state
	return nil
}
func (f *metadataFake) PurgeMetadataCache(context.Context, string, uint64) error {
	f.purges++
	f.state.Document = nil
	f.state.Validators = MetadataValidators{}
	f.state.FreshUntil = time.Time{}
	return nil
}
func (f *metadataFake) AdmitMetadata(context.Context, grants.Scope) (bool, error) {
	f.attempts++
	return f.allowed, f.admitErr
}
func (f *metadataFake) FetchMetadata(_ context.Context, _ string, v MetadataValidators) (MetadataResponse, error) {
	if f.forbidFetch {
		f.t.Fatal("metadata fetched before host admission")
	}
	f.fetches++
	f.validators = v
	if f.onFetch != nil {
		f.onFetch()
	}
	return f.response, f.fetchErr
}
func newMetadataFake(t *testing.T) (*metadataFake, *Metadata, grants.Scope, string) {
	t.Helper()
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	id := "https://agent.example/client.json"
	typ := "https://api.example/types/item"
	profile, err := resources.NewObjectProfile(resources.ObjectProfileSpec{Scope: scope, Resource: "https://api.example", Type: typ, Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read items"}}})
	if err != nil {
		t.Fatal(err)
	}
	f := &metadataFake{fake: &fake{t: t, p: policy.Tenant{Version: 1, MaxAccessTokenSeconds: 300, MaxGrantSeconds: 3600}, resource: resources.Resource{ID: "api", URI: "https://api.example", AccessTokenSeconds: 300}, profile: profile}, allowed: true, metadataPolicy: clients.MetadataPolicy{Version: 2, Mode: "hosts", Hosts: []string{"agent.example"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{typ}, MaxClients: 10, AccessTokenSeconds: 120}, response: MetadataResponse{Document: clients.MetadataDocument{ClientID: id, Name: "Agent", RedirectURIs: []string{"https://agent.example/cb"}}, Validators: MetadataValidators{ETag: `"v1"`}, FreshFor: time.Minute}}
	s, err := NewMetadata(f, f, f, f, scope)
	if err != nil {
		t.Fatal(err)
	}
	return f, s, scope, id
}
func TestCIMDAdmissionPrecedesCacheAndNetworkAccess(t *testing.T) {
	for _, mode := range []string{"foreign", "closed", "host boundary", "unavailable", "budget"} {
		t.Run(mode, func(t *testing.T) {
			f, s, scope, id := newMetadataFake(t)
			f.forbidFetch = true
			f.forbidCatalog = true
			f.forbidState = true
			want := clients.ErrMetadataDenied
			switch mode {
			case "foreign":
				scope.TenantID = "b"
				f.denyAccess = true
			case "closed":
				f.metadataPolicy = clients.DefaultMetadataPolicy()
			case "host boundary":
				id = "https://agent.example.evil/client.json"
			case "unavailable":
				f.admitErr = ErrUnavailable
				f.denyAccess = true
				want = clients.ErrMetadataUnavailable
			case "budget":
				f.allowed = false
				f.denyAccess = true
				want = clients.ErrMetadataUnavailable
			}
			if c, err := s.ResolveClient(context.Background(), scope, id, false); !errors.Is(err, want) || c.ID != "" || f.saves != 0 {
				t.Fatal("admission failed", err)
			}
		})
	}
}
func TestCIMDCacheRevalidationNoStoreAndFailureNeverWidenTrust(t *testing.T) {
	f, s, scope, id := newMetadataFake(t)
	ctx := context.Background()
	first, err := s.ResolveClient(ctx, scope, id, false)
	if err != nil || f.fetches != 1 || f.saves != 1 {
		t.Fatal("initial resolution", err)
	}
	second, err := s.ResolveClient(ctx, scope, id, false)
	if err != nil || second.MetadataDigest != first.MetadataDigest || f.fetches != 1 {
		t.Fatal("fresh cache not reused", err)
	}
	f.response = MetadataResponse{NotModified: true, Validators: MetadataValidators{ETag: `"v1"`}, FreshFor: time.Minute}
	if c, err := s.ResolveClient(ctx, scope, id, true); err != nil || c.MetadataDigest != first.MetadataDigest || f.validators.ETag != `"v1"` {
		t.Fatal("critical revalidation missing", err)
	}
	f.response.NoStore = true
	if _, err := s.ResolveClient(ctx, scope, id, true); err != nil || f.state.Document != nil || f.state.Validators != (MetadataValidators{}) || !f.state.FreshUntil.IsZero() {
		t.Fatal("no-store cache retained", err)
	}
	f.response = MetadataResponse{Document: clients.MetadataDocument{ClientID: id, Name: "New name", RedirectURIs: []string{"https://agent.example/cb"}}}
	c, err := s.ResolveClient(ctx, scope, id, false)
	if err != nil || c.MetadataDigest == first.MetadataDigest || f.validators != (MetadataValidators{}) {
		t.Fatal("no-store reused old response", err)
	}
	f.fetchErr = ErrUnavailable
	if c, err := s.ResolveClient(ctx, scope, id, true); !errors.Is(err, clients.ErrMetadataUnavailable) || c.ID != "" || f.state.Document != nil {
		t.Fatal("stale cache used after failure", err)
	}
	f.fetchErr = nil
	f.response.Document.ClientID = "https://other.example/client.json"
	if c, err := s.ResolveClient(ctx, scope, id, true); !errors.Is(err, clients.ErrMetadataDenied) || c.ID != "" {
		t.Fatal("mismatched identity accepted", err)
	}
}
func TestCIMDResolutionCannotCommitAcrossPolicyOrReplicaChanges(t *testing.T) {
	for _, change := range []string{"policy", "generation", "audit"} {
		t.Run(change, func(t *testing.T) {
			f, s, scope, id := newMetadataFake(t)
			f.onFetch = func() {
				switch change {
				case "policy":
					f.metadataPolicy.Version++
				case "generation":
					f.state.Generation++
				case "audit":
					f.commitErr = ErrUnavailable
				}
			}
			if c, err := s.ResolveClient(context.Background(), scope, id, true); err == nil || c.ID != "" {
				t.Fatal("uncommitted/raced metadata escaped")
			}
		})
	}
}
