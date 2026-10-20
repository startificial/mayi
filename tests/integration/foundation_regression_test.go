package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/app"
	"github.com/startificial/mayi/internal/services/administration"
)

func TestP2RuntimeCanOnlyConsumeAndRevokeStoredAuthority(t *testing.T) {
	e := setupFoundationDatabase(t)
	ctx := context.Background()
	txSeed, err := e.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer txSeed.Rollback(ctx)
	if _, err := txSeed.Exec(ctx, `INSERT INTO mayi.tenants VALUES('a','https://auth.example/t/a',1);
 INSERT INTO mayi.clients(tenant_id,client_id) VALUES('a','client');
 INSERT INTO mayi.grants(tenant_id,grant_id,client_id,subject,principal_type,resource,current_scopes,expires_at,current_object_ceiling)
 VALUES('a','grant','client','user:alice','user','https://api.example',ARRAY['read'],clock_timestamp()+interval '1 hour','`+fixtureObjectJSON+`');
 INSERT INTO mayi.grant_revisions(tenant_id,grant_id,revision,scopes,expires_at,object_ceiling)
 VALUES('a','grant',1,ARRAY['read'],clock_timestamp()+interval '1 hour','`+fixtureObjectJSON+`');
 INSERT INTO mayi.credentials(tenant_id,hash,kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,origin_code,object_ceiling,authorization_hash)
 VALUES('a','code','authorization_code','grant',1,'https://api.example','client',ARRAY['read'],clock_timestamp(),clock_timestamp()+interval '50 seconds','code','`+fixtureObjectJSON+`','`+secretHash("acodeworkflow")+`');
 INSERT INTO mayi.refresh_families(tenant_id,family_id,grant_id,revision,origin_code,absolute_deadline,idle_seconds,object_ceiling)
 VALUES('a','family','grant',1,'code',clock_timestamp()+interval '1 hour',120,'`+fixtureObjectJSON+`');
 INSERT INTO mayi.issuances(tenant_id,issuance_id,grant_id,revision,origin_code,source_credential,resource,scopes,expires_at,object_ceiling,token_hash)
 VALUES('a','issuance','grant',1,'code','code','https://api.example',ARRAY['read'],clock_timestamp()+interval '5 minutes','`+fixtureObjectJSON+`','`+secretHash("fixture-issuance")+`')`); err != nil {
		t.Fatal(err)
	}
	seedCodeApproval(t, txSeed, "a", "code")
	if err := txSeed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Check effective column privileges, so a future broad grant cannot leave
	// an untested identity/provenance field writable. The fixture migrates twice.
	var unsafe bool
	if err := e.db.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mayi' AND c.relname IN ('grants','credentials','refresh_families','issuances')
 AND a.attnum>0 AND NOT a.attisdropped
 AND a.attname<>CASE WHEN c.relname='credentials' THEN 'consumed' ELSE 'revoked' END
 AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE'))`).Scan(&unsafe); err != nil || unsafe {
		t.Fatal("runtime can update stored authority beyond lifecycle state", err)
	}
	for _, query := range []string{
		`UPDATE mayi.grants SET subject='user:mallory' WHERE tenant_id='a'`,
		`UPDATE mayi.grants SET client_id='client' WHERE tenant_id='a'`,
		`UPDATE mayi.grants SET current_scopes=ARRAY['write'] WHERE tenant_id='a'`,
		`UPDATE mayi.credentials SET pkce_challenge='replacement' WHERE tenant_id='a'`,
		`UPDATE mayi.credentials SET origin_code='code' WHERE tenant_id='a'`,
		`UPDATE mayi.credentials SET authorization_hash=NULL WHERE tenant_id='a'`,
		`UPDATE mayi.refresh_families SET origin_code='code' WHERE tenant_id='a'`,
		`UPDATE mayi.refresh_families SET absolute_deadline=absolute_deadline WHERE tenant_id='a'`,
		`UPDATE mayi.issuances SET source_credential='code' WHERE tenant_id='a'`,
		`UPDATE mayi.issuances SET origin_code='code' WHERE tenant_id='a'`,
	} {
		tx, err := e.db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('mayi.tenant_id','a',true)`); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, query)
		_ = tx.Rollback(ctx)
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("runtime authority mutation did not fail on privileges", query, err)
		}
	}
	// Actual issuance/replay concurrency is exercised elsewhere in the suite;
	// these updates prove the restricted grants still permit their state changes.
	tx, err := e.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('mayi.tenant_id','a',true)`); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE mayi.grants SET revoked=true WHERE tenant_id='a'`,
		`UPDATE mayi.credentials SET consumed=true WHERE tenant_id='a'`,
		`UPDATE mayi.refresh_families SET revoked=true WHERE tenant_id='a'`,
		`UPDATE mayi.issuances SET revoked=true WHERE tenant_id='a'`,
	} {
		if tag, err := tx.Exec(ctx, query); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("runtime lifecycle transition failed", query, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestP1RejectsOwnerSessionDisguisedAsRuntime(t *testing.T) {
	e := setupFoundationDatabase(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `GRANT mayi_p1_runtime TO mayi_p1_owner`); err != nil {
		t.Fatal(err)
	}
	defer e.admin.Exec(ctx, `REVOKE mayi_p1_runtime FROM mayi_p1_owner`)
	c, err := pgx.ParseConfig(os.Getenv("MAYI_P0_POSTGRES"))
	if err != nil {
		t.Fatal(err)
	}
	c.User = "mayi_p1_owner"
	c.RuntimeParams["role"] = "mayi_p1_runtime"
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var effective, session string
	if err := conn.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&effective, &session); err != nil || effective != "mayi_p1_runtime" || session != "mayi_p1_owner" {
		t.Fatal("invalid bypass fixture", effective, session, err)
	}
	if err := postgres.ValidateRuntime(ctx, conn, "mayi_p1_runtime"); !errors.Is(err, postgres.ErrDatabaseConfiguration) {
		t.Fatal("owner session admitted", err)
	}
	// Prove why checking current_user alone is insufficient.
	if _, err := conn.Exec(ctx, `SET ROLE mayi_p1_owner`); err != nil {
		t.Fatal(err)
	}
}

func TestP1RejectsInheritedMigrationColumnWrites(t *testing.T) {
	e := setupFoundationDatabase(t)
	ctx := context.Background()
	conn, err := e.db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := e.admin.Exec(ctx, `CREATE ROLE mayi_p1_columns NOLOGIN; GRANT mayi_p1_columns TO mayi_p1_runtime; GRANT UPDATE(sha256) ON mayi.schema_migrations TO mayi_p1_columns`); err != nil {
		t.Fatal(err)
	}
	defer e.admin.Exec(ctx, `REVOKE UPDATE(sha256) ON mayi.schema_migrations FROM mayi_p1_columns; REVOKE mayi_p1_columns FROM mayi_p1_runtime; DROP ROLE mayi_p1_columns`)
	var tableWrite, columnWrite bool
	if err := conn.QueryRow(ctx, `SELECT has_table_privilege(current_user,'mayi.schema_migrations','UPDATE'),has_column_privilege(current_user,'mayi.schema_migrations','sha256','UPDATE')`).Scan(&tableWrite, &columnWrite); err != nil || tableWrite || !columnWrite {
		t.Fatal("invalid inherited column fixture", err)
	}
	if err := postgres.ValidateRuntime(ctx, conn.Conn(), "mayi_p1_runtime"); !errors.Is(err, postgres.ErrDatabaseConfiguration) {
		t.Fatal("unsafe runtime admitted", err)
	}
	if err := postgres.ApplyMigrations(ctx, e.owner, "mayi_p1_runtime"); !errors.Is(err, postgres.ErrDatabaseConfiguration) {
		t.Fatal("unsafe migration role admitted", err)
	}
	if _, err := e.admin.Exec(ctx, `REVOKE UPDATE(sha256) ON mayi.schema_migrations FROM mayi_p1_columns`); err != nil {
		t.Fatal(err)
	}
	if err := postgres.ValidateRuntime(ctx, conn.Conn(), "mayi_p1_runtime"); err != nil {
		t.Fatal("repaired runtime rejected", err)
	}
	if err := postgres.ApplyMigrations(ctx, e.owner, "mayi_p1_runtime"); err != nil {
		t.Fatal("repaired migration rejected", err)
	}
}

func TestP2RejectsInheritedAuthorityUpdates(t *testing.T) {
	e := setupFoundationDatabase(t)
	ctx := context.Background()
	conn, err := e.db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := e.admin.Exec(ctx, `CREATE ROLE mayi_p2_authority_grants NOLOGIN; GRANT mayi_p2_authority_grants TO mayi_p1_runtime`); err != nil {
		t.Fatal(err)
	}
	defer e.admin.Exec(ctx, `REVOKE UPDATE(subject) ON mayi.grants FROM mayi_p2_authority_grants;
 REVOKE UPDATE ON mayi.credentials FROM mayi_p2_authority_grants;
 REVOKE UPDATE,DELETE ON mayi.proof_nonces,mayi.proof_replays FROM mayi_p2_authority_grants;
 REVOKE mayi_p2_authority_grants FROM mayi_p1_runtime; DROP ROLE mayi_p2_authority_grants`)
	for _, permission := range []string{"UPDATE(subject) ON mayi.grants", "UPDATE ON mayi.credentials", "UPDATE(expires_at) ON mayi.proof_nonces", "UPDATE ON mayi.proof_replays", "DELETE ON mayi.proof_nonces", "DELETE ON mayi.proof_replays"} {
		if _, err := e.admin.Exec(ctx, `GRANT `+permission+` TO mayi_p2_authority_grants`); err != nil {
			t.Fatal(err)
		}
		if err := postgres.ValidateRuntime(ctx, conn.Conn(), "mayi_p1_runtime"); !errors.Is(err, postgres.ErrDatabaseConfiguration) {
			t.Fatal("inherited authority update admitted at runtime", permission, err)
		}
		if err := postgres.ApplyMigrations(ctx, e.owner, "mayi_p1_runtime"); !errors.Is(err, postgres.ErrDatabaseConfiguration) {
			t.Fatal("inherited authority update admitted by migration", permission, err)
		}
		if _, err := e.admin.Exec(ctx, `REVOKE `+permission+` FROM mayi_p2_authority_grants`); err != nil {
			t.Fatal(err)
		}
	}
	if err := postgres.ValidateRuntime(ctx, conn.Conn(), "mayi_p1_runtime"); err != nil {
		t.Fatal("repaired authority privileges rejected", err)
	}
	if err := postgres.ApplyMigrations(ctx, e.owner, "mayi_p1_runtime"); err != nil {
		t.Fatal("repaired authority privileges could not migrate", err)
	}
}

func TestP1DisabledActiveVersionFailsReadinessAndStartup(t *testing.T) {
	e := setupFoundation(t)
	ctx := context.Background()
	server := e.server(t)
	request(t, os.Getenv("MAYI_P0_TRANSIT"), os.Getenv("MAYI_P0_TRANSIT_TOKEN"), "POST", "transit/keys/"+e.config.Tenants[0].KeyName+"/config", map[string]any{"min_encryption_version": 2}, http.StatusOK)
	if w := api(t, server.Handler, "GET", "/readyz", "", ""); w.Code != 503 {
		t.Fatal("disabled active version reported ready", w.Code)
	}
	lookup := func(k string) string { return e.secret[k] }
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if _, err := app.NewServer(ctx, e.config, e.db, lookup, logger); err == nil {
		t.Fatal("disabled active version accepted at startup")
	}
	scope, _ := app.NewIssuerScope(e.config.PublicOrigin, "a")
	clock := &testClock{time.Now()}
	service, _ := administration.New(e.store, e.keys["a"], clock)
	actor := administration.Actor{ID: "admin", Scope: scope, Permissions: []string{"keys:write"}}
	if err := service.PublishKey(ctx, actor, scope, 2); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Minute + time.Second)
	if err := service.ActivateKey(ctx, actor, scope, 2); err != nil {
		t.Fatal(err)
	}
	if w := api(t, server.Handler, "GET", "/readyz", "", ""); w.Code != 200 {
		t.Fatal("permitted active version not ready", w.Code)
	}
	if _, err := app.NewServer(ctx, e.config, e.db, lookup, logger); err != nil {
		t.Fatal("old verification key prevented startup", err)
	}
	keys, err := e.store.PublishedKeys(ctx, scope)
	if err != nil || len(keys) != 2 {
		t.Fatal("disabled signing version must remain published for verification", err)
	}
}

type blockedAuditOutput struct{ started, release chan struct{} }

func (w *blockedAuditOutput) Write(b []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(b), nil
}
func TestP1WorkerShutdownWithBlockedOutputLeavesLeaseUnacknowledged(t *testing.T) {
	e := setupFoundation(t)
	data, err := json.Marshal(e.config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := pgx.ParseConfig(os.Getenv("MAYI_P0_POSTGRES"))
	if err != nil {
		t.Fatal(err)
	}
	c.User = "mayi_p1_runtime"
	lookup := func(key string) string {
		if key == "MAYI_DATABASE_URL" {
			return "host=" + c.Host + " user=mayi_p1_runtime dbname=postgres sslmode=disable"
		}
		return e.secret[key]
	}
	output := &blockedAuditOutput{started: make(chan struct{}), release: make(chan struct{})}
	defer close(output.release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, []string{"worker", "-config", path}, lookup, output, io.Discard) }()
	select {
	case <-output.started:
	case err := <-done:
		t.Fatal("worker stopped before delivery", err)
	case <-time.After(5 * time.Second):
		t.Fatal("worker never attempted delivery")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked output prevented worker shutdown")
	}
	var leased, acknowledged int
	if err := e.admin.QueryRow(context.Background(), `SELECT count(*) FILTER(WHERE attempts=1),count(*) FILTER(WHERE delivered_at IS NOT NULL) FROM mayi.outbox_events`).Scan(&leased, &acknowledged); err != nil || leased != 1 || acknowledged != 0 {
		t.Fatal("canceled delivery acknowledged", leased, acknowledged, err)
	}
}

// heldRequestBody signals admission only when the real authenticated handler
// starts reading. This avoids a probe racing with requests for the last slot.
type heldRequestBody struct {
	entered chan<- struct{}
	release <-chan struct{}
	once    sync.Once
}

func (b *heldRequestBody) Read([]byte) (int, error) {
	b.once.Do(func() { b.entered <- struct{}{} })
	<-b.release
	return 0, io.EOF
}

func TestP1LivenessSurvivesPublicAdmissionSaturation(t *testing.T) {
	e := setupFoundation(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := app.NewServer(ctx, e.config, e.db, func(k string) string { return e.secret[k] }, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 100)
	release := make(chan struct{})
	var wg sync.WaitGroup
	defer func() { close(release); cancel(); wg.Wait() }()
	for range 100 {
		wg.Go(func() {
			body := &heldRequestBody{entered: entered, release: release}
			r := httptest.NewRequest("POST", "/admin/t/a/resources", body).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+e.tokens["a"])
			server.Handler.ServeHTTP(httptest.NewRecorder(), r)
		})
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for range 100 {
		select {
		case <-entered:
		case <-deadline.C:
			t.Fatal("not all requests reached the admitted handler")
		}
	}
	// Once all bodies are blocked, check admission without perturbing startup.
	if w := api(t, server.Handler, "GET", "/unknown", "", ""); w.Code != 503 || w.Header().Get("X-Request-ID") != "" {
		t.Fatal("public admission was not saturated", w.Code)
	}
	for _, method := range []string{"GET", "HEAD"} {
		if w := api(t, server.Handler, method, "/healthz", "", ""); w.Code != 200 {
			t.Fatal("liveness rejected during saturation", method, w.Code)
		}
	}
	for _, path := range []string{"/readyz", "/metrics"} {
		if w := api(t, server.Handler, "GET", path, "", ""); w.Code != 503 {
			t.Fatal("public admission bypassed", path, w.Code)
		}
	}
}
