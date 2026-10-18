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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/app"
	"github.com/startificial/mayi/internal/services/administration"
)

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

func TestP1DisabledActiveVersionFailsReadinessAndStartup(t *testing.T) {
	e := setupFoundation(t)
	ctx := context.Background()
	server := e.server(t)
	request(t, os.Getenv("MAYI_P0_TRANSIT"), os.Getenv("MAYI_P0_TRANSIT_TOKEN"), "POST", "transit/keys/"+e.config.Tenants[0].KeyName+"/config", map[string]any{"min_encryption_version": 2}, http.StatusNoContent)
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

func TestP1LivenessSurvivesPublicAdmissionSaturation(t *testing.T) {
	e := setupFoundation(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := app.NewServer(ctx, e.config, e.db, func(k string) string { return e.secret[k] }, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var held []*pgxpool.Conn
	for range e.db.Config().MaxConns {
		c, err := e.db.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	var wg sync.WaitGroup
	defer func() {
		cancel()
		for _, c := range held {
			c.Release()
		}
		wg.Wait()
	}()
	for range 100 {
		wg.Go(func() {
			r := httptest.NewRequest("GET", "/t/a/jwks", nil).WithContext(ctx)
			server.Handler.ServeHTTP(httptest.NewRecorder(), r)
		})
	}
	saturated := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// Unknown routes consume no dependency and finish immediately until all slots
		// are occupied. Admission rejection has no generated request ID.
		w := api(t, server.Handler, "GET", "/unknown", "", "")
		if w.Code == 503 && w.Header().Get("X-Request-ID") == "" {
			saturated = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !saturated {
		t.Fatal("failed to saturate public admission")
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
