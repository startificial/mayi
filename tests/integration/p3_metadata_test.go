package integration_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	domainauthorization "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/authorization"
)

// Synthetic public-HTTPS metadata replies are injected through the consuming
// port. PostgreSQL, OpenBao and all OAuth/consent/status paths remain real. The
// constrained transport and HTTP parsing/cache headers have separate wire tests.
type cimdSource struct {
	mu       sync.Mutex
	response administration.MetadataResponse
	err      error
	fetches  int
	before   func(int)
}

func (s *cimdSource) FetchMetadata(_ context.Context, _ string, v administration.MetadataValidators) (administration.MetadataResponse, error) {
	s.mu.Lock()
	s.fetches++
	count := s.fetches
	r, err, before := s.response, s.err, s.before
	r.Document.RedirectURIs = append([]string(nil), r.Document.RedirectURIs...)
	if v.ETag != "" && v.ETag == r.Validators.ETag && r.Document.ClientID != "" {
		r.NotModified = true
	}
	s.mu.Unlock()
	if before != nil {
		before(count)
	}
	return r, err
}
func (s *cimdSource) set(r administration.MetadataResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.response = r
	s.err = nil
}
func (s *cimdSource) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.fetches }

type cimdFixture struct {
	l          *liveProtocol
	metadata   *administration.Metadata
	management *administration.Service
	source     *cimdSource
	policy     clients.MetadataPolicy
	actor      administration.Actor
	id         string
	sequence   atomic.Int64
}

func newCIMD(t *testing.T) *cimdFixture {
	t.Helper()
	f := &cimdFixture{id: "https://app.example/" + strings.Repeat("client", 60) + "/metadata.json", source: &cimdSource{}}
	f.source.response = administration.MetadataResponse{Document: clients.MetadataDocument{ClientID: f.id, Name: "Unverified CIMD app", RedirectURIs: []string{"https://app.example/cb?provider=mayi"}}, Validators: administration.MetadataValidators{ETag: `"v1"`}, FreshFor: time.Minute}
	f.l = newLiveProtocol(t, func(e *foundation, scope grants.Scope) *administration.Metadata {
		m, err := administration.NewMetadata(e.store, f.source, e.store, clock{}, scope)
		if err != nil {
			t.Fatal(err)
		}
		f.metadata = m
		return m
	})
	var err error
	f.management, err = administration.New(f.l.e.store, profileKeys{t}, clock{})
	if err != nil {
		t.Fatal(err)
	}
	f.actor = administration.Actor{ID: "admin", Scope: f.l.proof.TenantIssuer, Permissions: []string{"clients:read", "clients:write"}}
	f.policy = clients.MetadataPolicy{Version: 1, Mode: "hosts", Hosts: []string{"app.example"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}, MaxClients: 10, AccessTokenSeconds: 300}
	f.policy, err = f.management.SetMetadataPolicy(context.Background(), f.actor, f.actor.Scope, f.policy)
	if err != nil {
		t.Fatal("publish metadata policy", err)
	}
	return f
}
func (f *cimdFixture) token(t *testing.T, code string, key *ecdsa.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"client_id": {f.id}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "resource": {"https://api.example"}}
	sign := func(nonce string) string {
		return proof(t, key, map[string]any{"nonce": nonce, "jti": fmt.Sprintf("cimd-token-proof-%020d", f.sequence.Add(1)), "htm": "POST", "htu": f.actor.Scope.Issuer + "/token"})
	}
	nonce := requireNonce(t, dpopPost(f.l.protocol.Token, form, sign("")), 400)
	return dpopPost(f.l.protocol.Token, form, sign(nonce))
}
func (f *cimdFixture) active(t *testing.T, access string) bool {
	t.Helper()
	w := protocolPost(f.l.protocol.Introspect, url.Values{"token": {access}, "resource": {"https://api.example"}}, "resource-server", f.l.resourceSecret)
	var result struct {
		Active bool `json:"active"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatal("status unavailable", w.Code)
	}
	return result.Active
}

func TestP3CIMDUnknownURLClientCachesAndCompletesLiveAuthorization(t *testing.T) {
	f := newCIMD(t)
	ctx := context.Background()
	scope := f.actor.Scope
	c, err := f.metadata.ResolveClient(ctx, scope, f.id, false)
	if err != nil || !c.Valid() || c.MetadataPolicyVersion != f.policy.Version {
		t.Fatal("unknown CIMD client unresolved", err)
	}
	count := f.source.count()
	replica, err := administration.NewMetadata(f.l.e.store, f.source, f.l.e.store, clock{}, scope)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := replica.ResolveClient(ctx, scope, f.id, false); err != nil || other.MetadataDigest != c.MetadataDigest || f.source.count() != count {
		t.Fatal("shared cache not reused", err)
	}
	key := proofKey(t)
	code := boundAuthorizationCode(t, f.l, key, f.id)
	w := f.token(t, code, key)
	var issued struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Access == "" || issued.Refresh == "" || !f.active(t, issued.Access) {
		t.Fatal("CIMD issuance/status failed", w.Code)
	}
	var requestDigest, codeDigest, issuanceDigest string
	if err := f.l.e.admin.QueryRow(ctx, `SELECT w.client_metadata_digest,c.client_metadata_digest,i.client_metadata_digest FROM mayi.authorization_transactions w JOIN mayi.credentials c ON c.tenant_id=w.tenant_id AND c.authorization_hash=w.handle_hash JOIN mayi.issuances i ON i.tenant_id=c.tenant_id AND i.source_credential=c.hash WHERE w.tenant_id='a' AND w.client_id=$1`, f.id).Scan(&requestDigest, &codeDigest, &issuanceDigest); err != nil || requestDigest != c.MetadataDigest || codeDigest != requestDigest || issuanceDigest != requestDigest {
		t.Fatal("metadata not immutably correlated", err)
	}
	// Changed display/security metadata invalidates prior credentials and online
	// access state once resolved; the existing grant ceiling never expands.
	f.source.set(administration.MetadataResponse{Document: clients.MetadataDocument{ClientID: f.id, Name: "New CIMD app", RedirectURIs: []string{"https://app.example/cb?provider=mayi"}}, Validators: administration.MetadataValidators{ETag: `"v2"`}, FreshFor: time.Minute})
	if _, err := replica.ResolveClient(ctx, scope, f.id, true); err != nil {
		t.Fatal(err)
	}
	if f.active(t, issued.Access) {
		t.Fatal("old token remained active after detected metadata change")
	}
	f.source.set(administration.MetadataResponse{Document: clients.MetadataDocument{ClientID: f.id, Name: "Unverified CIMD app", RedirectURIs: []string{"https://app.example/cb?provider=mayi"}}, Validators: administration.MetadataValidators{ETag: `"v3"`}, FreshFor: time.Minute})
	restored, err := replica.ResolveClient(ctx, scope, f.id, true)
	if err != nil || restored.MetadataDigest == c.MetadataDigest || f.active(t, issued.Access) {
		t.Fatal("restored document resurrected old credentials", err)
	}

}

func TestP3CIMDChangesBeforeConsentOrRedemptionFailWithoutConsumingCode(t *testing.T) {
	for _, stage := range []string{"consent", "redemption"} {
		t.Run(stage, func(t *testing.T) {
			f := newCIMD(t)
			ctx := context.Background()
			key := proofKey(t)
			if stage == "redemption" {
				code := boundAuthorizationCode(t, f.l, key, f.id)
				f.source.set(administration.MetadataResponse{Document: clients.MetadataDocument{ClientID: f.id, Name: "Changed name", RedirectURIs: []string{"https://app.example/cb?provider=mayi"}}, Validators: administration.MetadataValidators{ETag: `"v2"`}})
				requireProtocolError(t, f.token(t, code, key), 400, "invalid_grant")
				var consumed bool
				if err := f.l.e.admin.QueryRow(ctx, `SELECT consumed FROM mayi.credentials WHERE tenant_id='a' AND kind='authorization_code' AND client_id=$1`, f.id).Scan(&consumed); err != nil || consumed {
					t.Fatal("metadata rejection consumed code", err)
				}
				return
			}
			form := url.Values{"client_id": {f.id}, "response_type": {"code"}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "resource": {"https://api.example"}, "scope": {"read offline_access"}, "state": {"cimd-state-at-least-16"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}, "dpop_jkt": {thumbprint(t, key)}, "authorization_details": {`[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"workflow:123","actions":["read"]}]`}}
			w := protocolPost(f.l.protocol.Push, form, "", "")
			var pushed struct {
				URI string `json:"request_uri"`
			}
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &pushed) != nil {
				t.Fatal("PAR", w.Code)
			}
			started, err := f.l.consent.BeginPushed(ctx, authorization.PushedProof{TenantIssuer: f.actor.Scope, ClientID: f.id, ReferenceHash: secretHash(strings.TrimPrefix(pushed.URI, "urn:ietf:params:oauth:request_uri:")), BrowserBindingHash: f.l.proof.BrowserBindingHash})
			if err != nil {
				t.Fatal(err)
			}
			p := f.l.proof
			p.AuthorizationHash = secretHash(started.Handle)
			p.CSRFHash = secretHash(started.CSRFToken)
			view, err := f.l.consent.PrepareConsent(ctx, p)
			if err != nil || view.MetadataHost != "app.example" {
				t.Fatal("metadata host missing from consent", err)
			}
			f.source.set(administration.MetadataResponse{Document: clients.MetadataDocument{ClientID: f.id, Name: "Agent", RedirectURIs: []string{"https://app.example/changed"}}, Validators: administration.MetadataValidators{ETag: `"v2"`}})
			if result, err := f.l.consent.Decide(ctx, authorization.Decision{Proof: p, Approve: true}); !errors.Is(err, authorization.ErrDenied) || result.Code != "" {
				t.Fatal("metadata changed after presentation", err)
			}
			var n int
			if err := f.l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.credentials WHERE tenant_id='a' AND client_id=$1`, f.id).Scan(&n); err != nil || n != 0 {
				t.Fatal("code emitted after metadata change")
			}
		})
	}
}

func TestP3CIMDNoStoreFailureAndPolicyCutoffAreShared(t *testing.T) {
	f := newCIMD(t)
	ctx := context.Background()
	scope := f.actor.Scope
	f.source.mu.Lock()
	f.source.response.NoStore = true
	f.source.mu.Unlock()
	for range 2 {
		if _, err := f.metadata.ResolveClient(ctx, scope, f.id, false); err != nil {
			t.Fatal(err)
		}
	}
	if f.source.count() != 2 {
		t.Fatal("no-store reused metadata")
	}
	var empty bool
	if err := f.l.e.admin.QueryRow(ctx, `SELECT cache_document IS NULL AND etag='' AND last_modified='' AND fresh_until IS NULL FROM mayi.client_metadata_state WHERE tenant_id='a' AND client_id=$1`, f.id).Scan(&empty); err != nil || !empty {
		t.Fatal("no-store cache retained", err)
	}
	f.source.mu.Lock()
	f.source.err = administration.ErrUnavailable
	f.source.mu.Unlock()
	if c, err := f.metadata.ResolveClient(ctx, scope, f.id, true); !errors.Is(err, clients.ErrMetadataUnavailable) || c.ID != "" {
		t.Fatal("fetch failure revived a prior client", err)
	}
	f.source.set(administration.MetadataResponse{Document: clients.MetadataDocument{ClientID: f.id, Name: "Agent", RedirectURIs: []string{"https://app.example/cb?provider=mayi"}}, FreshFor: time.Minute})
	key := proofKey(t)
	code := boundAuthorizationCode(t, f.l, key, f.id)
	w := f.token(t, code, key)
	var issued struct {
		Access string `json:"access_token"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil {
		t.Fatal("issuance", w.Code)
	}
	f.policy.Hosts = []string{"other.example"}
	var err error
	f.policy, err = f.management.SetMetadataPolicy(ctx, f.actor, scope, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	before := f.source.count()
	if _, err := f.metadata.ResolveClient(ctx, scope, f.id, true); !errors.Is(err, clients.ErrMetadataDenied) || f.source.count() != before {
		t.Fatal("forbidden host fetched", err)
	}
	if f.active(t, issued.Access) {
		t.Fatal("policy removal did not immediately cut off online authority")
	}
	foreign := scope
	foreign.Issuer = "https://other.example/t/a"
	if _, err := f.metadata.ResolveClient(ctx, foreign, f.id, false); !errors.Is(err, clients.ErrMetadataDenied) {
		t.Fatal("foreign issuer admitted")
	}
}

func TestP3CIMDSlowResponsesCannotOverwriteAnotherReplicaOrPolicy(t *testing.T) {
	for _, mode := range []string{"replica", "policy"} {
		t.Run(mode, func(t *testing.T) {
			f := newCIMD(t)
			ctx := context.Background()
			entered, release := make(chan struct{}), make(chan struct{})
			f.source.mu.Lock()
			f.source.before = func(n int) {
				if n == 1 {
					close(entered)
					<-release
				}
			}
			f.source.mu.Unlock()
			result := make(chan error, 1)
			go func() { _, err := f.metadata.ResolveClient(ctx, f.actor.Scope, f.id, true); result <- err }()
			<-entered
			if mode == "replica" {
				f.source.set(administration.MetadataResponse{Document: clients.MetadataDocument{ClientID: f.id, Name: "New replica result", RedirectURIs: []string{"https://app.example/cb?provider=mayi"}}, FreshFor: time.Minute})
				replica, err := administration.NewMetadata(f.l.e.store, f.source, f.l.e.store, clock{}, f.actor.Scope)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := replica.ResolveClient(ctx, f.actor.Scope, f.id, true); err != nil {
					t.Fatal(err)
				}
			} else {
				p := clients.DefaultMetadataPolicy()
				p.Version = f.policy.Version
				if _, err := f.management.SetMetadataPolicy(ctx, f.actor, f.actor.Scope, p); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			if err := <-result; !errors.Is(err, clients.ErrMetadataDenied) {
				t.Fatal("stale response committed", err)
			}
			var n int
			if err := f.l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.client_metadata_state WHERE tenant_id='a'`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if mode == "policy" && n != 0 || mode == "replica" && n != 1 {
				t.Fatal("unexpected metadata state")
			}
		})
	}
}

func TestP3CIMDPolicyModesAuditRollbackAndDCRAdmission(t *testing.T) {
	f := newCIMD(t)
	ctx := context.Background()
	scope := f.actor.Scope
	if _, err := f.management.SetRegistrationPolicy(ctx, f.actor, scope, clients.RegistrationPolicy{Version: 1, Mode: "open", Resources: f.policy.Resources, AuthorizationDetailsTypes: f.policy.AuthorizationDetailsTypes, MaxClients: 10, AccessTokenSeconds: 300}); !errors.Is(err, administration.ErrDenied) {
		t.Fatal("public DCR bypassed host-only admission", err)
	}
	before := f.source.count()
	if _, err := f.metadata.ResolveClient(ctx, scope, "https://child.app.example/metadata.json", false); !errors.Is(err, clients.ErrMetadataDenied) || f.source.count() != before {
		t.Fatal("subdomain fetched under exact host policy", err)
	}
	f.policy.Mode = "admin_only"
	f.policy.Hosts = nil
	f.policy.ApprovedClients = []string{f.id}
	var err error
	f.policy, err = f.management.SetMetadataPolicy(ctx, f.actor, scope, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.metadata.ResolveClient(ctx, scope, f.id+"/other", false); !errors.Is(err, clients.ErrMetadataDenied) || f.source.count() != before {
		t.Fatal("administrator approval was not exact", err)
	}
	if _, err := f.l.e.admin.Exec(ctx, `CREATE FUNCTION mayi.reject_metadata_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_type='client_metadata_resolved' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END$$; CREATE TRIGGER reject_metadata_audit BEFORE INSERT ON mayi.audit_events FOR EACH ROW EXECUTE FUNCTION mayi.reject_metadata_audit()`); err != nil {
		t.Fatal(err)
	}
	if c, err := f.metadata.ResolveClient(ctx, scope, f.id, true); !errors.Is(err, clients.ErrMetadataUnavailable) || c.ID != "" {
		t.Fatal("unaudited metadata admitted", err)
	}
	var n int
	if err := f.l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.clients WHERE tenant_id='a' AND client_id=$1`, f.id).Scan(&n); err != nil || n != 0 {
		t.Fatal("failed metadata commit retained client")
	}
	if _, err := f.l.e.admin.Exec(ctx, `DROP TRIGGER reject_metadata_audit ON mayi.audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.metadata.ResolveClient(ctx, scope, f.id, true); err != nil {
		t.Fatal("exact administrator-approved identity rejected", err)
	}
	f.policy.Mode = "any"
	f.policy.ApprovedClients = nil
	f.policy, err = f.management.SetMetadataPolicy(ctx, f.actor, scope, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	other := "https://other.example/client.json"
	f.source.set(administration.MetadataResponse{Document: clients.MetadataDocument{ClientID: other, Name: "Other", RedirectURIs: []string{"https://other.example/callback"}}, FreshFor: time.Minute})
	if _, err := f.metadata.ResolveClient(ctx, scope, other, false); err != nil {
		t.Fatal("any-client policy rejected a valid public client", err)
	}
	foreign := f.actor
	foreign.Scope.TenantID = "b"
	if _, err := f.management.MetadataPolicy(ctx, foreign, scope); !errors.Is(err, administration.ErrDenied) {
		t.Fatal("foreign policy read")
	}
}

func TestP3CIMDLongURLAndRARTypeRetainExactIdentity(t *testing.T) {
	f := newCIMD(t)
	ctx := context.Background()
	typPrefix := "https://api.example/types/"
	typ := typPrefix + strings.Repeat("t", 2048-len(typPrefix))
	actor := f.actor
	actor.Permissions = append(actor.Permissions, "resources:write")
	if err := f.management.RegisterObjectProfile(ctx, actor, actor.Scope, "api", resources.ObjectProfileSpec{Scope: actor.Scope, Resource: "https://api.example", Type: typ, Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read items"}}}); err != nil {
		t.Fatal(err)
	}
	f.policy.AuthorizationDetailsTypes = []string{typ}
	var err error
	f.policy, err = f.management.SetMetadataPolicy(ctx, f.actor, f.actor.Scope, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "https://app.example/"
	first := prefix + strings.Repeat("c", 2048-len(prefix))
	second := first[:2047] + "d"
	for _, id := range []string{first, second} {
		f.source.set(administration.MetadataResponse{Document: clients.MetadataDocument{ClientID: id, Name: "Long client", RedirectURIs: []string{"https://app.example/cb?provider=mayi"}}, FreshFor: time.Minute})
		c, err := f.metadata.ResolveClient(ctx, f.actor.Scope, id, false)
		if err != nil || c.ID != id {
			t.Fatal("long identity or vocabulary failed", err)
		}
	}
	var n int
	if err := f.l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.client_object_types WHERE tenant_id='a' AND type_uri=$1 AND client_id=ANY($2::text[])`, typ, []string{first, second}).Scan(&n); err != nil || n != 2 {
		t.Fatal("index changed full-string identity", err)
	}
}

func TestP3CIMDPersistenceRejectsCounterfeitMetadataPin(t *testing.T) {
	f := newCIMD(t)
	ctx := context.Background()
	if _, err := f.metadata.ResolveClient(ctx, f.actor.Scope, f.id, false); err != nil {
		t.Fatal(err)
	}
	objects, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: f.actor.Scope, Resource: "https://api.example", Details: []grants.ObjectDetail{{Type: "https://api.example/types/fixture/v1", Identifier: "workflow:123", Actions: []string{"read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var policyVersion uint64
	if err := f.l.e.admin.QueryRow(ctx, `SELECT policy_version FROM mayi.tenants WHERE tenant_id=$1`, f.actor.Scope.TenantID).Scan(&policyVersion); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	p, err := domainauthorization.NewPushed(domainauthorization.PushedSpec{ID: "metadata-pin", ReferenceHash: strings.Repeat("a", 64), PolicyVersion: policyVersion, CreatedAt: now, ExpiresAt: now.Add(time.Minute), Request: domainauthorization.Request{TenantIssuer: f.actor.Scope, ClientID: f.id, ClientMetadataDigest: strings.Repeat("b", 64), RedirectURI: "https://app.example/cb?provider=mayi", ResourceURI: "https://api.example", PermissionScopes: []string{"read"}, PKCEChallenge: challenge, BindingThumbprint: thumbprint(t, proofKey(t)), State: "metadata-pin-proof-state", ObjectCeiling: objects}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.l.e.store.RunAuthorization(ctx, f.actor.Scope, func(tx authorization.Transaction) error { return tx.CreatePushed(ctx, p) }); err == nil {
		t.Fatal("forged metadata pin persisted")
	}
	var count int
	if err := f.l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.pushed_requests WHERE tenant_id='a' AND reference_hash=$1`, p.Snapshot().ReferenceHash).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected pin changed state")
	}
}
