package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	clientservice "github.com/startificial/mayi/internal/services/clients"
)

func TestP3PublicRegistrationPolicyQuotaAndAtomicAudit(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	scope := l.proof.TenantIssuer
	management, err := administration.New(l.e.store, profileKeys{t}, clock{})
	if err != nil {
		t.Fatal(err)
	}
	actor := administration.Actor{ID: "admin", Scope: scope, Permissions: []string{"clients:read", "clients:write"}}
	token := strings.Repeat("r", 43)
	sum := sha256.Sum256([]byte(token))
	credentials, err := cryptoadapter.NewRegistrationCredentials(scope, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	service, err := administration.NewRegistration(l.e.store, credentials, l.e.store, scope)
	if err != nil {
		t.Fatal(err)
	}
	otherReplica, err := administration.NewRegistration(l.e.store, credentials, l.e.store, scope)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := oauth.NewRegistration(service, scope)
	if err != nil {
		t.Fatal(err)
	}
	input := clients.PublicRegistration{Name: "Unverified agent", RedirectURIs: []string{"https://app.example/cb?provider=mayi"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}}
	if c, err := service.Register(ctx, scope, "", input); !errors.Is(err, administration.ErrDenied) || c.ID != "" {
		t.Fatal("default admission not closed", err)
	}
	p := clients.RegistrationPolicy{Version: 1, Mode: "open", Resources: input.Resources, AuthorizationDetailsTypes: input.AuthorizationDetailsTypes, MaxClients: 1, AccessTokenSeconds: 300, RequireInitialAccess: true}
	p, err = management.SetRegistrationPolicy(ctx, actor, scope, p)
	if err != nil || p.Version != 2 {
		t.Fatal("policy not set", err)
	}
	if _, err := management.SetRegistrationPolicy(ctx, actor, scope, clients.RegistrationPolicy{Version: 1, Mode: "admin_only"}); !errors.Is(err, administration.ErrConflict) {
		t.Fatal("stale policy accepted", err)
	}
	foreign := actor
	foreign.Scope = grants.Scope{TenantID: "b", Issuer: "https://auth.example/t/b"}
	if _, err := management.RegistrationPolicy(ctx, foreign, scope); !errors.Is(err, administration.ErrDenied) {
		t.Fatal("foreign policy read")
	}
	for _, credential := range []string{"", strings.Repeat("x", 43)} {
		if c, err := service.Register(ctx, scope, credential, input); !errors.Is(err, administration.ErrInitialAccess) || c.ID != "" {
			t.Fatal("initial access bypass", err)
		}
	}
	// A deliberately failing audit must roll back client and quota provenance.
	if _, err := l.e.admin.Exec(ctx, `CREATE FUNCTION mayi.reject_registration_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_type='public_client_registered' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END$$; CREATE TRIGGER reject_registration_audit BEFORE INSERT ON mayi.audit_events FOR EACH ROW EXECUTE FUNCTION mayi.reject_registration_audit()`); err != nil {
		t.Fatal(err)
	}
	if c, err := service.Register(ctx, scope, token, input); !errors.Is(err, administration.ErrUnavailable) || c.ID != "" {
		t.Fatal("unaudited client escaped", err)
	}
	if _, err := l.e.admin.Exec(ctx, `DROP TRIGGER reject_registration_audit ON mayi.audit_events`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.dynamic_clients WHERE tenant_id='a'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed commit consumed quota")
	}
	if err := l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.clients WHERE tenant_id='a' AND client_id LIKE 'agent-%'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("audit failure left an orphan client")
	}
	// Replicas compete for the final slot under the same tenant lock.
	type result struct {
		client clients.Client
		err    error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, s := range []*administration.Registration{service, otherReplica} {
		wg.Add(1)
		go func(s *administration.Registration) {
			defer wg.Done()
			<-start
			c, err := s.Register(ctx, scope, token, input)
			results <- result{c, err}
		}(s)
	}
	close(start)
	wg.Wait()
	close(results)
	winner := clients.Client{}
	denied := 0
	for result := range results {
		if result.err == nil {
			if winner.ID != "" {
				t.Fatal("quota raced")
			}
			winner = result.client
		} else if errors.Is(result.err, administration.ErrRegistrationQuota) {
			denied++
		} else {
			t.Fatal(result.err)
		}
	}
	if winner.ID == "" || denied != 1 || !winner.RequireBinding || winner.AuthMethod != "none" || winner.Machine || winner.Introspection {
		t.Fatal("unsafe registration")
	}
	if err := l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.audit_events WHERE tenant_id='a' AND event_type='public_client_registered' AND object_ref=$1`, winner.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("registration audit not atomic", err)
	}
	var attempts int
	if err := l.e.admin.QueryRow(ctx, `SELECT used FROM mayi.request_budgets WHERE tenant_id='a' AND operation='registration'`).Scan(&attempts); err != nil || attempts < 1 {
		t.Fatal("replicas did not share registration budget", err)
	}
	principal, err := l.clients.Authenticate(ctx, clientservice.Proof{ClientID: winner.ID, Method: "none", Audience: scope.Issuer + "/token", Operation: "token"})
	if err != nil || principal.Client.ID != winner.ID {
		t.Fatal("registered public client cannot authenticate", err)
	}
	// The existing live PAR/consent/code path and exact callback rules admit it.
	code := boundAuthorizationCode(t, l, proofKey(t), winner.ID)
	if code == "" {
		t.Fatal("no code for registered client")
	}
	// Open admission still rejects a supplied foreign credential. Wire failures
	// never return a client or secret and never disclose tenant catalog contents.
	p.RequireInitialAccess = false
	p.MaxClients = 3
	p, err = management.SetRegistrationPolicy(ctx, actor, scope, p)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"client_name":"Agent","redirect_uris":["https://agent.example/cb"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"mayi_resource_ids":["api"],"authorization_details_types":["https://api.example/types/fixture/v1"]}`
	request := httptest.NewRequest("POST", scope.Issuer+"/register", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 43))
	w := httptest.NewRecorder()
	handler.Register(w, request)
	requireProtocolError(t, w, 401, "invalid_token")
	request = httptest.NewRequest("POST", scope.Issuer+"/register", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	handler.Register(w, request)
	var response map[string]json.RawMessage
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response["client_secret"] != nil || response["registration_access_token"] != nil || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("unsafe DCR response", w.Code)
	}
	request = httptest.NewRequest("POST", scope.Issuer+"/register", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "bearer "+token)
	w = httptest.NewRecorder()
	handler.Register(w, request)
	if w.Code != 201 {
		t.Fatal("case-insensitive initial-access scheme rejected", w.Code)
	}
	closed := clients.RegistrationPolicy{Version: p.Version, Mode: "admin_only"}
	if _, err := management.SetRegistrationPolicy(ctx, actor, scope, closed); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Register(ctx, scope, "", input); !errors.Is(err, administration.ErrDenied) {
		t.Fatal("closed policy ignored", err)
	}
}
