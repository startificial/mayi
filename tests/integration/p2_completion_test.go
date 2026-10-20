package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oidc"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/adapters/outbound/egress"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/app"
	domain "github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authentication"
	"github.com/startificial/mayi/internal/services/authorization"
	clientservice "github.com/startificial/mayi/internal/services/clients"
	"github.com/startificial/mayi/internal/services/delivery"
	"github.com/startificial/mayi/internal/services/discovery"
	"github.com/startificial/mayi/internal/services/grants"
	"github.com/startificial/mayi/internal/services/tokens"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestP2RequestBudgetsAreAtomicAcrossReplicasAndTenantScoped(t *testing.T) {
	e := setupFoundationDatabase(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.tenants VALUES('a','https://auth.example/t/a',1),('b','https://auth.example/t/b',1)`); err != nil {
		t.Fatal(err)
	}
	rules := authentication.DefaultBudgetRules()
	for i := range rules {
		rules[i].Limit = 7
		rules[i].WindowSeconds = 3600
	}
	second, err := postgres.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	first, err := authentication.NewAdmission(e.store, rules)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := authentication.NewAdmission(second, rules)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := app.NewIssuerScope("https://auth.example", "a")
	for _, operation := range []string{"login", "token", "introspection"} {
		for _, dimension := range []string{"ip", "client", "user"} {
			results := make(chan error, 32)
			var group sync.WaitGroup
			for i := range 32 {
				group.Add(1)
				go func() {
					defer group.Done()
					service := first
					if i%2 == 1 {
						service = replica
					}
					results <- service.Check(ctx, scope, operation, dimension, "same-principal")
				}()
			}
			group.Wait()
			close(results)
			allowed := 0
			for err := range results {
				if err == nil {
					allowed++
				} else if !errors.Is(err, authentication.ErrLimited) {
					t.Fatal("shared counter unavailable", err)
				}
			}
			if allowed != 7 {
				t.Fatal("replicas exceeded budget", operation, dimension, allowed)
			}
			other, _ := app.NewIssuerScope("https://auth.example", "b")
			if err := first.Check(ctx, other, operation, dimension, "same-principal"); err != nil {
				t.Fatal("foreign tenant shared budget", err)
			}
		}
	}
	var leaked bool
	if err := e.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.request_budgets WHERE key_hash LIKE '%same-principal%')`).Scan(&leaked); err != nil || leaked {
		t.Fatal("raw admission key persisted", err)
	}
	if _, err := e.admin.Exec(ctx, `ALTER TABLE mayi.request_budgets RENAME TO unavailable_request_budgets`); err != nil {
		t.Fatal(err)
	}
	if err := first.Check(ctx, scope, "token", "client", "new-client"); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatal("missing shared state did not fail closed", err)
	}
}

func TestP2CredentialBoundResourceFallbackAndAdminScopeCutoff(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	code := l.code(t, true)
	// A conflicting audience must neither issue nor consume the credential.
	bad := protocolPost(l.protocol.Token, url.Values{"client_id": {"web"}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "resource": {"https://other.example"}}, "", "")
	if bad.Code != 400 {
		t.Fatal("foreign audience accepted", bad.Code)
	}
	form := url.Values{"client_id": {"web"}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}}
	w := protocolPost(l.protocol.Token, form, "", "")
	var issued protocolTokens
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Access == "" || issued.Refresh == "" {
		t.Fatal("bound code fallback", w.Code, w.Body.String())
	}
	w = protocolPost(l.protocol.Token, url.Values{"client_id": {"web"}, "grant_type": {"refresh_token"}, "refresh_token": {issued.Refresh}}, "", "")
	if w.Code != 200 {
		t.Fatal("bound refresh fallback", w.Code, w.Body.String())
	}
	if _, err := l.e.admin.Exec(ctx, `UPDATE mayi.resource_scopes SET requires_admin=true WHERE tenant_id='a' AND name='read'`); err != nil {
		t.Fatal(err)
	}
	status := protocolPost(l.protocol.Introspect, url.Values{"token": {issued.Access}, "resource": {"https://api.example"}}, "resource-server", l.resourceSecret)
	if strings.TrimSpace(status.Body.String()) != `{"active":false}` {
		t.Fatal("admin-only scope remained active", status.Body.String())
	}
}
func TestP2ConnectedGrantUsageAndTenantAdministratorListing(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	l.redeem(t, l.code(t, false))
	service, err := grants.New(l.e.store, clock{}, l.proof.TenantIssuer)
	if err != nil {
		t.Fatal(err)
	}
	actor := grants.Operator{ID: "operator", Scope: l.proof.TenantIssuer, Permissions: []string{"grants:read"}}
	records, err := service.AdminList(ctx, actor, "")
	if err != nil || len(records) != 1 || records[0].TokensIssued != 1 || records[0].LastIssuedAt == nil {
		t.Fatal("grant usage missing", records, err)
	}
	actor.Scope.TenantID = "b"
	if rows, err := service.AdminList(ctx, actor, ""); !errors.Is(err, grants.ErrDenied) || rows != nil {
		t.Fatal("foreign administrator loaded grants", err)
	}
	actor.Scope = l.proof.TenantIssuer
	actor.Permissions = nil
	if rows, err := service.AdminList(ctx, actor, ""); !errors.Is(err, grants.ErrDenied) || rows != nil {
		t.Fatal("unprivileged administrator loaded grants", err)
	}
}

func TestP2MachinePolicyManagementRequiresAuthorityAndCutsOffExistingTokens(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	if _, err := l.e.admin.Exec(ctx, `INSERT INTO mayi.clients(tenant_id,client_id,name,redirect_uris,access_token_seconds,auth_method,machine) VALUES('a','client:managed','Managed worker',ARRAY[]::text[],300,'client_secret_basic',true);
 INSERT INTO mayi.client_resources VALUES('a','client:managed','api');
 INSERT INTO mayi.client_object_types VALUES('a','client:managed','api','https://api.example/types/fixture/v1')`); err != nil {
		t.Fatal(err)
	}
	service, err := tokens.NewMachinePolicies(l.e.store, l.proof.TenantIssuer)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := oauth.DecodeObjectRequest(`[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"workflow:123","actions":["read"]}]`, l.proof.TenantIssuer, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	command := tokens.MachineAuthorization{ClientID: "client:managed", Resource: "https://api.example", Scopes: []string{"read"}, Objects: objects}
	actor := tokens.MachineOperator{Scope: l.proof.TenantIssuer, ID: "operator", Permissions: []string{"clients:write"}}
	foreign := actor
	foreign.Scope.TenantID = "b"
	if err := service.Configure(ctx, foreign, command, false); !errors.Is(err, tokens.ErrMachinePolicyDenied) {
		t.Fatal("foreign machine policy write", err)
	}
	if err := service.Configure(ctx, actor, command, false); err != nil {
		t.Fatal("configure machine authority", err)
	}
	secret, err := l.clients.Rotate(ctx, clientservice.Operator{Scope: l.proof.TenantIssuer, ID: "operator", Permissions: []string{"clients:write"}}, command.ClientID, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := protocolPost(l.protocol.Token, url.Values{"grant_type": {"client_credentials"}, "resource": {command.Resource}, "scope": {"read"}}, command.ClientID, secret)
	var issued protocolTokens
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Access == "" {
		t.Fatal("managed machine issuance", w.Code, w.Body.String())
	}
	if err := service.Configure(ctx, actor, command, true); err != nil {
		t.Fatal("remove machine authority", err)
	}
	status := protocolPost(l.protocol.Introspect, url.Values{"token": {issued.Access}, "resource": {command.Resource}}, "resource-server", l.resourceSecret)
	if strings.TrimSpace(status.Body.String()) != `{"active":false}` {
		t.Fatal("removed machine policy remained active", status.Body.String())
	}
}

func TestP2BoundPARRejectsConflictsAndCrossResourceReferenceUse(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	scope := l.proof.TenantIssuer
	bound, err := oauth.NewResourcePushed(scope, l.clients, l.consent, "https://api.example", "api", l.proofs)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"client_id": {"web"}, "response_type": {"code"}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "scope": {"read"}, "state": {"downstream-state-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}, "authorization_details": {`[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"workflow:123","actions":["read"]}]`}}
	form.Set("resource", "https://other.example")
	w := protocolPost(bound.Push, form, "", "")
	if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_target") {
		t.Fatal("bound PAR accepted conflict", w.Body.String())
	}
	form.Del("resource")
	w = protocolPost(bound.Push, form, "", "")
	var pushed struct {
		URI string `json:"request_uri"`
	}
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &pushed) != nil {
		t.Fatal("bound PAR omitted audience", w.Code, w.Body.String())
	}
	proof := authorization.PushedProof{TenantIssuer: scope, ClientID: "web", ReferenceHash: secretHash(strings.TrimPrefix(pushed.URI, "urn:ietf:params:oauth:request_uri:")), BrowserBindingHash: l.proof.BrowserBindingHash, ResourceURI: "https://other.example"}
	if out, err := l.consent.BeginPushed(ctx, proof); !errors.Is(err, authorization.ErrDenied) || out.Handle != "" {
		t.Fatal("bound route consumed another audience", err)
	}
	proof.ResourceURI = "https://api.example"
	if out, err := l.consent.BeginPushed(ctx, proof); err != nil || out.Handle == "" {
		t.Fatal("conflicting binding consumed PAR", err)
	}
}

func TestP2AuthorizationOptionsCannotBeMissingOrSwappedAtCommit(t *testing.T) {
	for _, mode := range []string{"missing pushed options", "missing workflow options", "swapped offline approval"} {
		t.Run(mode, func(t *testing.T) {
			e, service, request, proof := setupAuthorization(t)
			ctx := context.Background()
			table := "pushed_options"
			body := "RETURN NULL;"
			if mode != "missing pushed options" {
				table = "authorization_options"
			}
			if mode == "swapped offline approval" {
				body = "NEW.offline_access:=NOT NEW.offline_access;RETURN NEW;"
			}
			if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fault_options() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN `+body+` END$$; CREATE TRIGGER fault_options BEFORE INSERT ON mayi.`+table+` FOR EACH ROW EXECUTE FUNCTION mayi.fault_options()`); err != nil {
				t.Fatal(err)
			}
			pushed, err := service.Push(ctx, request)
			if mode == "missing pushed options" {
				if err == nil || pushed.Reference != "" {
					t.Fatal("missing PAR options committed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.BeginPushed(ctx, authorization.PushedProof{TenantIssuer: request.TenantIssuer, ClientID: request.ClientID, ReferenceHash: secretHash(pushed.Reference), BrowserBindingHash: proof.BrowserBindingHash})
			if err == nil || out.Handle != "" {
				t.Fatal("workflow options not atomically bound", err)
			}
			var consumed bool
			if err := e.admin.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM mayi.pushed_requests WHERE tenant_id='a'`).Scan(&consumed); err != nil || consumed {
				t.Fatal("options failure consumed PAR", err)
			}
		})
	}
}

func TestP2IncrementalConsentAppendsRevisionWithoutExpandingOldRefresh(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	if _, err := l.e.admin.Exec(ctx, `INSERT INTO mayi_resource.permissions SELECT tenant_id,issuer,resource,subject,object_type,'workflow:124',actions FROM mayi_resource.permissions;
 INSERT INTO mayi_resource.labels(tenant_id,issuer,resource,object_type,identifier,name) SELECT tenant_id,issuer,resource,object_type,'workflow:124','Second object' FROM mayi_resource.labels`); err != nil {
		t.Fatal(err)
	}
	old := l.redeem(t, l.code(t, true))
	next := l.redeem(t, l.objectCode(t, "workflow:124", true))
	if old.Access == "" || next.Access == "" {
		t.Fatal("missing incremental credentials")
	}
	var roots, revisions int
	if err := l.e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.grants WHERE tenant_id='a'),(SELECT count(*) FROM mayi.grant_revisions WHERE tenant_id='a')`).Scan(&roots, &revisions); err != nil || roots != 1 || revisions != 2 {
		t.Fatal("incremental approval created parallel roots", roots, revisions, err)
	}
	service, err := grants.New(l.e.store, clock{}, l.proof.TenantIssuer)
	if err != nil {
		t.Fatal(err)
	}
	connected, err := service.List(ctx, grants.BrowserProof{Scope: l.proof.TenantIssuer, SessionHash: l.proof.SessionHash, BrowserHash: l.proof.BrowserBindingHash})
	if err != nil || len(connected) != 1 || connected[0].Revision != 2 || len(connected[0].Objects.Snapshot().Details) != 2 {
		t.Fatal("connected authorization did not extend", err)
	}
	expansion := `[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"workflow:124","actions":["read"]}]`
	w := protocolPost(l.protocol.Token, url.Values{"client_id": {"web"}, "grant_type": {"refresh_token"}, "refresh_token": {old.Refresh}, "resource": {"https://api.example"}, "authorization_details": {expansion}}, "", "")
	if w.Code != 400 {
		t.Fatal("later consent enlarged old refresh", w.Code, w.Body.String())
	}
	w = protocolPost(l.protocol.Token, url.Values{"client_id": {"web"}, "grant_type": {"refresh_token"}, "refresh_token": {old.Refresh}}, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "workflow:124") {
		t.Fatal("old refresh changed revision or was consumed by rejected expansion", w.Code, w.Body.String())
	}
	if err := service.Revoke(ctx, grants.BrowserProof{Scope: l.proof.TenantIssuer, SessionHash: l.proof.SessionHash, BrowserHash: l.proof.BrowserBindingHash}, connected[0].ID); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{old.Access, next.Access} {
		w := protocolPost(l.protocol.Introspect, url.Values{"token": {token}, "resource": {"https://api.example"}}, "resource-server", l.resourceSecret)
		if strings.TrimSpace(w.Body.String()) != `{"active":false}` {
			t.Fatal("root revocation missed revision", w.Body.String())
		}
	}
}

func TestP2SecurityAuditRetainsTrustedCorrelationAndNoCredentials(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	code := l.code(t, false)
	security, err := delivery.NewSecurity(l.e.store)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	audit, err := middleware.NewAudit(security, []domain.Scope{l.proof.TenantIssuer}, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	router := http.NewServeMux()
	router.HandleFunc("POST /t/a/token", l.protocol.Token)
	router.HandleFunc("POST /t/a/introspect", l.protocol.Introspect)
	handler := middleware.NewTelemetry(logger).Wrap(audit.Wrap(router))
	call := func(path string, form url.Values, id, secret string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://auth.example/t/a/"+path, strings.NewReader(form.Encode()))
		r.RemoteAddr = "192.0.2.8:4321"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Request-ID", "attacker-value")
		r.Header.Set("X-Forwarded-For", "198.51.100.1")
		r.Header.Set("User-Agent", "MayiProtocolTest/1.0")
		if id != "" {
			r.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	issued := call("token", url.Values{"client_id": {"web"}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}}, "", "")
	if issued.Code != 200 {
		t.Fatal(issued.Code, issued.Body.String())
	}
	var request, ip, agent, user, client, resource string
	if err := l.e.admin.QueryRow(ctx, `SELECT request_id,remote_ip,user_agent,user_id,client_id,resource FROM mayi.audit_events WHERE event_type='token_issued' ORDER BY event_id DESC LIMIT 1`).Scan(&request, &ip, &agent, &user, &client, &resource); err != nil || request != issued.Header().Get("X-Request-ID") || ip != "192.0.2.8" || agent != "MayiProtocolTest/1.0" || user != "user:alice" || client != "web" || resource != "https://api.example" {
		t.Fatal("trusted audit correlation lost", request, ip, agent, user, client, resource, err)
	}
	denied := call("token", url.Values{"client_id": {"web"}, "grant_type": {"password"}}, "", "")
	if denied.Code != 400 || !strings.Contains(denied.Body.String(), "unsupported_grant_type") {
		t.Fatal("unsupported grant error contract", denied.Code, denied.Body.String())
	}
	var count int
	if err := l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.audit_events a JOIN mayi.outbox_events o USING(tenant_id,event_id) WHERE request_id=$1 AND event_type='http_request_denied' AND status_code=400`, denied.Header().Get("X-Request-ID")).Scan(&count); err != nil || count != 1 {
		t.Fatal("denial audit missing", count, err)
	}
	inactive := call("introspect", url.Values{"token": {"unknown-token"}, "resource": {"https://api.example"}}, "resource-server", l.resourceSecret)
	if inactive.Code != 200 {
		t.Fatal(inactive.Code, inactive.Body.String())
	}
	if err := l.e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.audit_events a JOIN mayi.outbox_events o USING(tenant_id,event_id) WHERE request_id=$1 AND event_type='introspection_inactive' AND client_id='resource-server'`, inactive.Header().Get("X-Request-ID")).Scan(&count); err != nil || count != 1 {
		t.Fatal("inactive introspection audit missing", count, err)
	}
	var leaked bool
	if err := l.e.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.audit_events a WHERE to_jsonb(a)::text LIKE '%'||$1||'%' OR to_jsonb(a)::text LIKE '%'||$2||'%')`, code, l.resourceSecret).Scan(&leaked); err != nil || leaked {
		t.Fatal("raw credential in audit", err)
	}
}

func TestP2LiveDiscoveryAdvertisesOnlyTheEnforcedProfile(t *testing.T) {
	l := newLiveProtocol(t)
	service, err := discovery.New(l.e.store)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := oidc.NewLive(service, l.proof.TenantIssuer, true)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.Metadata(w, httptest.NewRequest("GET", l.proof.TenantIssuer.Issuer+"/.well-known/openid-configuration", nil))
	var metadata map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &metadata) != nil {
		t.Fatal("live discovery unavailable", w.Code)
	}
	if metadata["issuer"] != l.proof.TenantIssuer.Issuer || metadata["require_pushed_authorization_requests"] != true || metadata["authorization_response_iss_parameter_supported"] != true {
		t.Fatal("discovery disagrees with enforcement", metadata)
	}
	types, ok := metadata["authorization_details_types_supported"].([]any)
	if !ok || len(types) != 1 || types[0] != "https://api.example/types/fixture/v1" {
		t.Fatal("registered RAR profile missing", metadata)
	}
	if _, ok := metadata["userinfo_endpoint"]; ok {
		t.Fatal("unsupported UserInfo advertised")
	}
}

func TestP2ProtocolBoundaryErrorsAreStableAndCredentialFree(t *testing.T) {
	l := newLiveProtocol(t)
	for _, c := range []struct {
		endpoint string
		form     url.Values
		status   int
		code     string
	}{
		{"token", url.Values{"client_id": {"web"}, "grant_type": {"password"}}, 400, "unsupported_grant_type"},
		{"token", url.Values{"client_id": {"missing"}, "grant_type": {"authorization_code"}, "code": {"raw-credential-must-not-leak"}}, 401, "invalid_client"},
		{"token", url.Values{"client_id": {"web"}, "grant_type": {"authorization_code"}, "code": {"raw-credential-must-not-leak"}, "code_verifier": {verifier}}, 400, "invalid_grant"},
		{"token", url.Values{"client_id": {"web"}, "grant_type": {"authorization_code"}, "code": {"raw-credential-must-not-leak"}, "scope": {"read read"}}, 400, "invalid_scope"},
		{"introspect", url.Values{"client_id": {"web"}, "token": {"raw-credential-must-not-leak"}, "resource": {"https://api.example"}}, 401, "invalid_client"},
	} {
		t.Run(c.endpoint+"/"+c.code, func(t *testing.T) {
			handler := http.HandlerFunc(l.protocol.Token)
			if c.endpoint == "introspect" {
				handler = l.protocol.Introspect
			}
			w := protocolPost(handler, c.form, "", "")
			if w.Code != c.status || !strings.Contains(w.Body.String(), `"error":"`+c.code+`"`) || strings.Contains(w.Body.String(), "raw-credential-must-not-leak") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("protocol error contract", w.Code, w.Body.String())
			}
			if c.status == 401 && w.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing client challenge")
			}
		})
	}
	r := httptest.NewRequest("POST", l.proof.TenantIssuer.Issuer+"/token", strings.NewReader("client_id=web&client_id=web&grant_type=authorization_code"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	l.protocol.Token(w, r)
	if w.Code != 400 || strings.Contains(w.Body.String(), "raw-credential") {
		t.Fatal("duplicate form accepted")
	}
}

func TestP2FailedClientAuthenticationConsumesSharedClientBudget(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	rules := authentication.DefaultBudgetRules()
	for i := range rules {
		rules[i].Limit = 3
		rules[i].WindowSeconds = 3600
	}
	admission, err := authentication.NewAdmission(l.e.store, rules)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := cryptoadapter.NewSecretHasher([]cryptoadapter.HashKey{{Version: 1, Key: []byte(strings.Repeat("k", 32)), Active: true}})
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := cryptoadapter.NewClientSecrets(l.proof.TenantIssuer, hash)
	if err != nil {
		t.Fatal(err)
	}
	assertions, err := cryptoadapter.NewClientAssertions(egress.NewRegisteredKeys(true))
	if err != nil {
		t.Fatal(err)
	}
	service, err := clientservice.New(l.e.store, clock{}, assertions, secrets, l.proof.TenantIssuer, admission)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := service.Authenticate(ctx, clientservice.Proof{ClientID: "resource-server", Method: "client_secret_basic", Secret: "incorrect", Operation: "introspection"}); !errors.Is(err, clientservice.ErrDenied) {
			t.Fatal("invalid secret was not denied", err)
		}
	}
	if _, err := service.Authenticate(ctx, clientservice.Proof{ClientID: "resource-server", Method: "client_secret_basic", Secret: l.resourceSecret, Operation: "introspection"}); !errors.Is(err, authentication.ErrLimited) {
		t.Fatal("failed authentications bypassed client budget", err)
	}
}
