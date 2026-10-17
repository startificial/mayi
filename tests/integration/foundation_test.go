package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/adapters/outbound/signing"
	"github.com/startificial/mayi/internal/app"
	"github.com/startificial/mayi/internal/domain/audit"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	domaintokens "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/delivery"
	"github.com/startificial/mayi/internal/services/tokens"
)

type foundation struct {
	admin, owner, db *pgxpool.Pool
	store            *postgres.Store
	config           app.Config
	keys             map[string]*signing.Ring
	secret           map[string]string
	tokens           map[string]string
	log              bytes.Buffer
}

func setupFoundation(t *testing.T) *foundation {
	t.Helper()
	needed(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, os.Getenv("MAYI_P0_POSTGRES"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.Exec(ctx, `DROP SCHEMA IF EXISTS mayi CASCADE;
 DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='mayi_p1_owner') THEN CREATE ROLE mayi_p1_owner LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='mayi_p1_runtime') THEN CREATE ROLE mayi_p1_runtime LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS; END IF; END $$;
 GRANT CREATE ON DATABASE postgres TO mayi_p1_owner`)
	if err != nil {
		t.Fatal(err)
	}
	open := func(role string, validate bool) *pgxpool.Pool {
		c, err := pgxpool.ParseConfig(os.Getenv("MAYI_P0_POSTGRES"))
		if err != nil {
			t.Fatal(err)
		}
		c.ConnConfig.User = role
		c.MaxConns = 6
		if validate {
			c.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error { return postgres.ValidateRuntime(ctx, conn, role) }
		}
		pool, err := pgxpool.NewWithConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		return pool
	}
	owner := open("mayi_p1_owner", false)
	if err := postgres.ApplyMigrations(ctx, owner, "mayi_p1_runtime"); err != nil {
		t.Fatal("migrate", err)
	}
	if err := postgres.ApplyMigrations(ctx, owner, "mayi_p1_runtime"); err != nil {
		t.Fatal("idempotent migrate", err)
	}
	db := open("mayi_p1_runtime", true)
	if err := db.Ping(ctx); err != nil {
		t.Fatal("runtime validation", err)
	}
	t.Cleanup(func() { db.Close(); owner.Close(); admin.Close() })
	store, _ := postgres.New(db)
	e := &foundation{admin: admin, owner: owner, db: db, store: store, keys: map[string]*signing.Ring{}, secret: map[string]string{}, tokens: map[string]string{}}
	e.config = app.Config{PublicOrigin: "https://auth.example", ListenAddress: "127.0.0.1:8080", RuntimeRole: "mayi_p1_runtime", DatabaseMaxConnections: 6, AllowInsecureLoopback: true, TransitAddress: os.Getenv("MAYI_P0_TRANSIT")}
	address := os.Getenv("MAYI_P0_TRANSIT")
	root := os.Getenv("MAYI_P0_TRANSIT_TOKEN")
	if !bytes.Contains(request(t, address, root, "GET", "sys/mounts", nil, 200), []byte(`"transit/"`)) {
		request(t, address, root, "POST", "sys/mounts/transit", map[string]string{"type": "transit"}, 204)
	}
	for _, id := range []string{"a", "b"} {
		scope, _ := app.NewIssuerScope(e.config.PublicOrigin, id)
		name := "p1-" + id + "-" + time.Now().Format("150405.000000000")
		name = strings.ReplaceAll(name, ".", "-")
		request(t, address, root, "POST", "transit/keys/"+name, map[string]any{"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false}, 200)
		request(t, address, root, "POST", "transit/keys/"+name+"/rotate", map[string]any{}, 200)
		policy := `path "transit/keys/` + name + `" { capabilities = ["read"] } path "transit/sign/` + name + `" { capabilities = ["update"] }`
		request(t, address, root, "PUT", "sys/policies/acl/"+name, map[string]string{"policy": policy}, 204)
		raw := request(t, address, root, "POST", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "10m"}, 200)
		var issued struct {
			Auth struct {
				Token string `json:"client_token"`
			} `json:"auth"`
		}
		if err := json.Unmarshal(raw, &issued); err != nil {
			t.Fatal(err)
		}
		env := "MAYI_" + strings.ToUpper(id) + "_TRANSIT_TOKEN"
		e.secret[env] = issued.Auth.Token
		var versions []*signing.Transit
		for _, v := range []int{1, 2} {
			s, err := signing.New(ctx, signing.Config{Address: address, Key: name, Token: issued.Auth.Token, Version: v, Scope: scope, AllowLoopbackHTTP: true}, &http.Client{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			versions = append(versions, s)
		}
		ring, err := signing.NewRing(scope, versions, store)
		if err != nil {
			t.Fatal(err)
		}
		e.keys[id] = ring
		ownerStore, _ := postgres.New(owner)
		provisioner, _ := administration.New(ownerStore, ring, &testClock{time.Now()})
		if err := provisioner.ProvisionTenant(ctx, administration.Actor{ID: "operator", Scope: scope, Permissions: []string{"tenants:provision"}}, scope, 1); err != nil {
			t.Fatal("provision", err)
		}
		token := strings.Repeat(id, 43)
		e.tokens[id] = token
		digest := sha256.Sum256([]byte(token))
		e.config.Tenants = append(e.config.Tenants, app.TenantConfig{ID: id, KeyName: name, KeyVersions: []int{1, 2}, InitialKeyVersion: 1, TransitTokenEnv: env, Administrators: []app.AdministratorConfig{{ID: "admin", TokenSHA256: hex.EncodeToString(digest[:]), Permissions: []string{"policy:read", "policy:write", "resources:read", "resources:write", "clients:read", "clients:write", "keys:write"}}}})
	}
	return e
}
func (e *foundation) server(t *testing.T) *http.Server {
	t.Helper()
	server, err := app.NewServer(context.Background(), e.config, e.db, func(name string) string { return e.secret[name] }, slog.New(slog.NewJSONHandler(&e.log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return server
}
func api(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestP1MigrationsOwnershipAndTenantIsolation(t *testing.T) {
	e := setupFoundation(t)
	h := e.server(t).Handler
	resource := `{"id":"api","uri":"https://api.example","name":"API","scopes":[{"name":"read","description":"Read objects"}],"access_token_seconds":300,"require_binding":true}`
	for _, id := range []string{"a", "b"} {
		w := api(t, h, "POST", "/admin/t/"+id+"/resources", e.tokens[id], resource)
		if w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	client := `{"id":"web","name":"Web client","redirect_uris":["https://app.example/callback"],"resources":["api"],"access_token_seconds":300,"enabled":true}`
	if w := api(t, h, "POST", "/admin/t/a/clients", e.tokens["a"], client); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, path := range []string{"/admin/t/b/resources/api", "/admin/t/b/clients/web", "/admin/t/b/policy"} {
		if w := api(t, h, "GET", path, e.tokens["a"], ""); w.Code != 403 {
			t.Fatal("cross tenant read", path, w.Code)
		}
	}
	if w := api(t, h, "POST", "/admin/t/b/resources", e.tokens["a"], resource); w.Code != 403 {
		t.Fatal("cross tenant write", w.Code)
	}
	if w := api(t, h, "GET", "/admin/t/a/policy", "", ""); w.Code != 401 {
		t.Fatal("anonymous", w.Code)
	}
	if w := api(t, h, "GET", "/admin/t/b/clients/web", e.tokens["b"], ""); w.Code != 404 {
		t.Fatal("client leaked across tenant", w.Code)
	}
	ctx := context.Background()
	tx, err := e.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('mayi.tenant_id','a',true)`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mayi.resources WHERE tenant_id='b'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("RLS leaked", err, count)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mayi.client_resources VALUES('a','web','missing')`); err == nil {
		t.Fatal("foreign resource relation accepted")
	}
	_ = tx.Rollback(ctx)
	for _, sql := range []string{`CREATE TABLE mayi.bad(id integer)`, `UPDATE mayi.schema_migrations SET sha256='tamper'`, `UPDATE mayi.tenants SET issuer='https://evil.example'`, `TRUNCATE mayi.audit_events`} {
		if _, err := e.db.Exec(ctx, sql); err == nil {
			t.Fatal("runtime exceeded permissions", sql)
		}
	}
	if _, err := e.admin.Exec(ctx, `UPDATE mayi.tenants SET issuer='https://evil.example' WHERE tenant_id='a'`); err == nil {
		t.Fatal("issuer mutable even as owner")
	}
	if e.log.String() == "" || strings.Contains(e.log.String(), e.tokens["a"]) || strings.Contains(e.log.String(), e.secret["MAYI_A_TRANSIT_TOKEN"]) {
		t.Fatal("telemetry missing or leaked credentials")
	}
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }
func TestP1RotationPublicationAndStableDiscovery(t *testing.T) {
	e := setupFoundation(t)
	h := e.server(t).Handler
	ctx := context.Background()
	scope, _ := app.NewIssuerScope(e.config.PublicOrigin, "a")
	clock := &testClock{time.Now()}
	service, _ := administration.New(e.store, e.keys["a"], clock)
	actor := administration.Actor{ID: "admin", Scope: scope, Permissions: []string{"keys:write"}}
	if err := service.PublishKey(ctx, actor, scope, 2); err != nil {
		t.Fatal(err)
	}
	if err := service.ActivateKey(ctx, actor, scope, 2); !errors.Is(err, administration.ErrConflict) {
		t.Fatal("unpublished overlap bypass", err)
	}
	w := api(t, h, "GET", "/.well-known/oauth-authorization-server/t/a", "", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var metadata map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &metadata)
	if metadata["issuer"] != scope.Issuer || metadata["jwks_uri"] != scope.Issuer+"/jwks" || metadata["token_endpoint"] != nil || metadata["authorization_endpoint"] != nil {
		t.Fatal("incorrect preview metadata", metadata)
	}
	keyset := api(t, h, "GET", "/t/a/jwks", "", "")
	if keyset.Code != 200 {
		t.Fatal(keyset.Code)
	}
	aKeys, _ := e.store.PublishedKeys(ctx, scope)
	bScope, _ := app.NewIssuerScope(e.config.PublicOrigin, "b")
	bKeys, _ := e.store.PublishedKeys(ctx, bScope)
	if len(aKeys) != 2 || len(bKeys) != 1 || bytes.Contains(keyset.Body.Bytes(), []byte(bKeys[0].ID)) {
		t.Fatal("key isolation or publication failed")
	}
	clock.now = clock.now.Add(time.Minute + time.Second)
	if err := service.ActivateKey(ctx, actor, scope, 2); err != nil {
		t.Fatal(err)
	}
	if version, err := e.store.ActiveSigningKey(ctx, scope); err != nil || version != 2 {
		t.Fatal("activation", version, err)
	}
	claims := domaintokens.AccessClaims{ID: "rotation-proof", Scope: scope, GrantID: "proof", Revision: 1, Subject: "user:alice", PrincipalType: "user", ClientID: "web", Resource: "https://api.example", Scopes: []string{"read"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute)}
	rawToken, err := e.keys["a"].SignAccessToken(ctx, claims)
	if err != nil {
		t.Fatal("real rotated signing", err)
	}
	parsed, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Headers[0].KeyID != aKeys[1].ID {
		t.Fatal("rotated token used old key")
	}
	var jwks jose.JSONWebKeySet
	if json.Unmarshal(keyset.Body.Bytes(), &jwks) != nil {
		t.Fatal("JWKS decode")
	}
	key := jwks.Key(parsed.Headers[0].KeyID)
	if len(key) != 1 {
		t.Fatal("rotated public key missing")
	}
	var verified map[string]any
	if err := parsed.Claims(key[0].Key, &verified); err != nil || verified["iss"] != scope.Issuer {
		t.Fatal("rotated signature verification", err)
	}
	if keys, _ := e.store.PublishedKeys(ctx, scope); len(keys) != 2 {
		t.Fatal("old key removed")
	}
	foreign := actor
	foreign.Scope = bScope
	if err := service.ActivateKey(ctx, foreign, scope, 1); !errors.Is(err, administration.ErrDenied) {
		t.Fatal("foreign key activation", err)
	}
	r := httptest.NewRequest("GET", "/t/a/jwks", nil)
	r.Host = "evil.example"
	r.Header.Set("Forwarded", "host=evil.example;proto=http")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != 200 || !bytes.Equal(keyset.Body.Bytes(), out.Body.Bytes()) {
		t.Fatal("host controlled discovery")
	}
	if w := api(t, h, "GET", "/t/a/.well-known/openid-configuration", "", ""); w.Code != 404 {
		t.Fatal("unimplemented OP advertised")
	}
	if w := api(t, h, "GET", "/readyz", "", ""); w.Code != 200 {
		t.Fatal("readiness", w.Code, w.Body.String())
	}
}
func TestP1AuditOutboxAtomicFailureAndFencedRetry(t *testing.T) {
	e := setupFoundation(t)
	ctx := context.Background()
	scope, _ := app.NewIssuerScope(e.config.PublicOrigin, "a")
	clock := &testClock{time.Now()}
	s, _ := administration.New(e.store, e.keys["a"], clock)
	actor := administration.Actor{ID: "admin", Scope: scope, Permissions: []string{"resources:write"}}
	r := resources.Resource{ID: "rollback", URI: "https://api.example", Name: "API", AccessTokenSeconds: 300, RequireBinding: true, Scopes: []resources.Scope{{Name: "read", Description: "Read objects"}}}
	_, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_outbox() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test outbox failure'; END$$; CREATE TRIGGER fail BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_outbox()`)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateResource(ctx, actor, scope, r); err == nil {
		t.Fatal("outbox failure acknowledged resource creation")
	}
	var count int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.resources WHERE resource_id='rollback'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial state committed", err, count)
	}
	if _, err := e.admin.Exec(ctx, `DROP TRIGGER fail ON mayi.outbox_events`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateResource(ctx, actor, scope, r); err != nil {
		t.Fatal(err)
	}
	first, ok, err := e.store.ClaimEvent(ctx, scope, clock.now, time.Minute)
	if err != nil || !ok {
		t.Fatal("claim", err)
	}
	second, ok, err := e.store.ClaimEvent(ctx, scope, clock.now.Add(time.Minute+time.Second), time.Minute)
	if err != nil || !ok || first.Event.ID != second.Event.ID || second.Attempt != first.Attempt+1 {
		t.Fatal("lease retry", err)
	}
	if err := e.store.CompleteEvent(ctx, first, clock.now.Add(time.Minute+2*time.Second)); err == nil {
		t.Fatal("stale worker acknowledged new lease")
	}
	if err := e.store.CompleteEvent(ctx, second, clock.now.Add(time.Minute+2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(ctx, `UPDATE mayi.audit_events SET event_type='tamper'`); err == nil {
		t.Fatal("runtime modified audit")
	}
	if _, err := e.admin.Exec(ctx, `DELETE FROM mayi.audit_events`); err == nil {
		t.Fatal("audit delete allowed")
	}
	clock.now = clock.now.Add(3 * time.Minute)
	sink := &captureSink{}
	worker, _ := delivery.New(e.store, sink, clock, scope)
	if _, err := worker.Drain(ctx, scope, 100); err != nil {
		t.Fatal(err)
	}
	for _, event := range sink.events {
		if event.Scope != scope {
			t.Fatal("worker crossed tenant")
		}
	}
}

type captureSink struct{ events []audit.Event }

func (s *captureSink) Deliver(_ context.Context, e audit.Event) error {
	s.events = append(s.events, e)
	return nil
}
func TestP1CommandUsesExternalDatabaseAndRejectsMigrationTampering(t *testing.T) {
	e := setupFoundation(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(e.config)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	config, _ := pgxpool.ParseConfig(os.Getenv("MAYI_P0_POSTGRES"))
	config.ConnConfig.User = "mayi_p1_owner"
	// pgx ConnString includes the modified User only through explicit formatting.
	ownerDSN := "host=" + config.ConnConfig.Host + " user=mayi_p1_owner dbname=postgres sslmode=disable"
	lookup := func(key string) string {
		if key == "MAYI_MIGRATION_DATABASE_URL" {
			return ownerDSN
		}
		return e.secret[key]
	}
	var output bytes.Buffer
	if err := app.Run(ctx, []string{"migrate", "-config", path}, lookup, &output, io.Discard); err != nil {
		t.Fatal("operator migration command", err)
	}
	if _, err := e.admin.Exec(ctx, `UPDATE mayi.schema_migrations SET sha256='tampered' WHERE version=1`); err != nil {
		t.Fatal(err)
	}
	if err := postgres.ApplyMigrations(ctx, e.owner, "mayi_p1_runtime"); err == nil {
		t.Fatal("tampered migration accepted")
	}
	conn, err := e.db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if err := postgres.ValidateRuntime(ctx, conn.Conn(), "mayi_p1_runtime"); err == nil {
		t.Fatal("runtime accepted tampered migration")
	}
}

func TestP1PolicyUpdateSerializesAndRejectsStaleVersions(t *testing.T) {
	e := setupFoundation(t)
	ctx := context.Background()
	scope, _ := app.NewIssuerScope(e.config.PublicOrigin, "a")
	s, _ := administration.New(e.store, e.keys["a"], &testClock{time.Now()})
	actor := administration.Actor{ID: "admin", Scope: scope, Permissions: []string{"policy:read", "policy:write"}}
	p, err := s.Policy(ctx, actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { _, err := s.SetPolicy(ctx, actor, scope, p); results <- err }()
	}
	wins, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			wins++
		} else if errors.Is(err, administration.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("concurrent policy overwrite", wins, conflicts)
	}
	current, err := s.Policy(ctx, actor, scope)
	if err != nil || current.Version != p.Version+1 {
		t.Fatal("policy version", current, err)
	}
	invalid := policy.Tenant{Version: current.Version, MaxAccessTokenSeconds: 901, MaxGrantSeconds: 3600}
	if _, err := s.SetPolicy(ctx, actor, scope, invalid); !errors.Is(err, administration.ErrInvalid) {
		t.Fatal("invalid policy persisted")
	}
}
func TestP1StartupAndReadinessFailClosed(t *testing.T) {
	e := setupFoundation(t)
	server := e.server(t)
	c := e.config
	c.PublicOrigin = "https://changed.example"
	if _, err := app.NewServer(context.Background(), c, e.db, func(k string) string { return e.secret[k] }, slog.New(slog.NewJSONHandler(io.Discard, nil))); err == nil {
		t.Fatal("changed issuer accepted at startup")
	}
	request(t, os.Getenv("MAYI_P0_TRANSIT"), os.Getenv("MAYI_P0_TRANSIT_TOKEN"), "POST", "auth/token/revoke", map[string]string{"token": e.secret["MAYI_A_TRANSIT_TOKEN"]}, 204)
	if w := api(t, server.Handler, "GET", "/readyz", "", ""); w.Code != 503 {
		t.Fatal("unavailable signer reported ready", w.Code)
	}
	if w := api(t, server.Handler, "GET", "/healthz", "", ""); w.Code != 200 {
		t.Fatal("liveness depended on signer")
	}
}

func TestP1ExpandedSchemaPreservesAtomicIssuanceAndEnqueuesAudit(t *testing.T) {
	e := setupFoundation(t)
	ctx := context.Background()
	scope, _ := app.NewIssuerScope(e.config.PublicOrigin, "a")
	tx, err := e.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('mayi.tenant_id','a',true)`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO mayi.clients(tenant_id,client_id) VALUES('a','client');
 INSERT INTO mayi.grants(tenant_id,grant_id,client_id,subject,principal_type,resource,current_scopes,expires_at) VALUES('a','grant','client','user:alice','user','https://api.example',ARRAY['read'],clock_timestamp()+interval '1 hour');
 INSERT INTO mayi.grant_revisions VALUES('a','grant',1,ARRAY['read'],clock_timestamp()+interval '1 hour')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO mayi.credentials(tenant_id,hash,kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,pkce_challenge,redirect_uri,binding_thumbprint,origin_code)
 VALUES('a','code','authorization_code','grant',1,'https://api.example','client',ARRAY['read'],clock_timestamp()-interval '1 second',clock_timestamp()+interval '50 seconds',$1,'https://client.example/cb','binding','code')`, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	service, err := app.NewIssuance(e.store, clock{}, e.keys["a"], cryptoadapter.NewMaterialSource(), e.store, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Redeem(ctx, tokens.Command{Caller: tokens.Caller{Scope: scope, ClientID: "client", BindingThumbprint: "binding"}, Kind: tokens.AuthorizationCode, CredentialHash: "code", Resource: "https://api.example", Verifier: verifier, Scopes: []string{"read"}})
	if err != nil || result.AccessToken == "" {
		t.Fatal("expanded schema issuance", err)
	}
	var count int
	err = e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.outbox_events o JOIN mayi.audit_events a USING(tenant_id,event_id) WHERE a.tenant_id='a' AND a.event_type='token_issued'`).Scan(&count)
	if err != nil || count != 1 {
		t.Fatal("issuance audit not enqueued", count, err)
	}
}
