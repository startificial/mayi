package integration_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/app"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authorization"
)

type consentHook struct {
	owner  authorization.ObjectConsentAuthority
	before func()
}

func (h consentHook) WithObjectConsent(ctx context.Context, q authorization.ObjectConsentQuery, fn func(context.Context, domain.ObjectConsentProjection) error) error {
	return h.owner.WithObjectConsent(ctx, q, func(ctx context.Context, p domain.ObjectConsentProjection) error {
		if h.before != nil {
			h.before()
		}
		return fn(ctx, p)
	})
}

func postgresConsentFixture(t *testing.T) (*foundation, *postgres.ResourceConsent, authorization.AccessProof) {
	t.Helper()
	e, _, proof, _ := objectConsentFixture(t)
	ctx := context.Background()
	data, err := os.ReadFile("../../deploy/resource-authority.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, string(data)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.admin.Exec(context.Background(), `DROP SCHEMA mayi_resource CASCADE`) })
	if _, err := e.admin.Exec(ctx, `
 GRANT USAGE ON SCHEMA mayi_resource TO mayi_p1_runtime;
 GRANT SELECT ON ALL TABLES IN SCHEMA mayi_resource TO mayi_p1_runtime;
 GRANT UPDATE(lock_marker) ON mayi_resource.authorities,mayi_resource.labels TO mayi_p1_runtime;
 INSERT INTO mayi_resource.authorities(tenant_id,issuer,resource,subject) VALUES('a','https://auth.example/t/a','https://api.example','user:alice');
 INSERT INTO mayi_resource.permissions VALUES('a','https://auth.example/t/a','https://api.example','user:alice','https://api.example/types/fixture/v1','workflow:123',ARRAY['read','write']);
 INSERT INTO mayi_resource.labels(tenant_id,issuer,resource,object_type,identifier,name) VALUES('a','https://auth.example/t/a','https://api.example','https://api.example/types/fixture/v1','workflow:123','Resource title');`); err != nil {
		t.Fatal(err)
	}
	// A single connection makes accidental nested acquisition fail deterministically.
	c := e.db.Config()
	c.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	e.store, err = postgres.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	a, err := postgres.NewResourceConsent(e.store, []postgres.ResourceConsentConfig{{Scope: proof.TenantIssuer, Resource: "https://api.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Check(ctx); err != nil {
		t.Fatal("unsafe resource contract", err)
	}
	return e, a, proof
}

func TestP2PostgresResourceConsentSharesAtomicTransactionAndOneConnection(t *testing.T) {
	e, a, p := postgresConsentFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	hook := consentHook{owner: a, before: func() {
		for _, table := range []string{"authorities", "labels"} {
			tx, err := e.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `SELECT * FROM mayi_resource.`+table+` FOR UPDATE NOWAIT`)
			var locked *pgconn.PgError
			if !errors.As(err, &locked) || locked.Code != "55P03" {
				t.Fatal("owner state not guarded", table, err)
			}
			_ = tx.Rollback(ctx)
		}
	}}
	svc, err := app.NewObjectAuthorization(e.store, clock{}, hook)
	if err != nil {
		t.Fatal(err)
	}
	view, err := svc.PrepareConsent(ctx, p)
	if err != nil || len(view.Objects) != 1 || view.Objects[0].Name != "Resource title" || view.PermissionVersion != 2 {
		t.Fatal("guarded display", view, err)
	}
	result, err := svc.Decide(ctx, authorization.Decision{Proof: p, Approve: true})
	if err != nil || result.Code == "" {
		t.Fatal("atomic approval", err)
	}
	if _, err := e.admin.Exec(ctx, `UPDATE mayi_resource.permissions SET actions=ARRAY['write']`); err != nil {
		t.Fatal("guard not released", err)
	}
	var version uint64
	if err := e.admin.QueryRow(ctx, `SELECT version FROM mayi_resource.authorities`).Scan(&version); err != nil || version != 3 {
		t.Fatal("permission generation not advanced", version, err)
	}
}

func TestP2PostgresResourceConsentConnectionLossCannotCommitMayi(t *testing.T) {
	e, a, p := postgresConsentFixture(t)
	ctx := context.Background()
	hook := consentHook{owner: a, before: func() {
		var killed bool
		err := e.admin.QueryRow(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='mayi_p1_runtime' AND state='idle in transaction' AND query LIKE 'SELECT name FROM mayi_resource.labels%'`).Scan(&killed)
		if err != nil || !killed {
			t.Fatal("did not terminate guard connection", err)
		}
	}}
	svc, err := app.NewObjectAuthorization(e.store, clock{}, hook)
	if err != nil {
		t.Fatal(err)
	}
	view, err := svc.PrepareConsent(ctx, p)
	if err == nil || view.ClientID != "" || len(view.Objects) != 0 {
		t.Fatal("lost guard disclosed display", err)
	}
	var bound bool
	if err := e.admin.QueryRow(ctx, `SELECT consent_session_hash IS NOT NULL FROM mayi.authorization_transactions WHERE tenant_id='a' AND handle_hash=$1`, p.AuthorizationHash).Scan(&bound); err != nil || bound {
		t.Fatal("lost guard committed Mayi state", err)
	}
}

func TestP2PostgresResourceConsentDeniesBeforeLabelsAndPreservesIsolation(t *testing.T) {
	for _, mode := range []string{"missing permission", "missing authority", "disabled authority", "forbidden", "foreign tenant", "foreign issuer", "foreign resource"} {
		t.Run(mode, func(t *testing.T) {
			e, a, p := postgresConsentFixture(t)
			ctx := context.Background()
			var sql string
			switch mode {
			case "missing permission":
				sql = `DELETE FROM mayi_resource.permissions`
			case "missing authority":
				sql = `DELETE FROM mayi_resource.permissions; DELETE FROM mayi_resource.authorities`
			case "disabled authority":
				sql = `UPDATE mayi_resource.authorities SET enabled=false`
			case "forbidden":
				sql = `UPDATE mayi_resource.permissions SET actions=ARRAY['write']`
			}
			if sql != "" {
				if _, err := e.admin.Exec(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.admin.Exec(ctx, `REVOKE SELECT ON mayi_resource.labels FROM mayi_p1_runtime`); err != nil {
				t.Fatal(err)
			}
			q := authorization.ObjectConsentQuery{TenantIssuer: p.TenantIssuer, Subject: "user:alice", ClientID: "web", AuthorizationHash: p.AuthorizationHash}
			details := []grants.ObjectDetail{{Type: "https://api.example/types/fixture/v1", Identifier: "workflow:123", Actions: []string{"read"}}}
			resource := "https://api.example"
			if mode == "foreign tenant" {
				q.TenantIssuer.TenantID = "b"
			}
			if mode == "foreign issuer" {
				q.TenantIssuer.Issuer = "https://other.example/t/a"
			}
			if mode == "foreign resource" {
				resource += "/other"
			}
			var err error
			q.Ceiling, err = grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: q.TenantIssuer, Resource: resource, Details: details})
			if err != nil {
				t.Fatal(err)
			}
			err = a.WithObjectConsent(ctx, q, func(context.Context, domain.ObjectConsentProjection) error {
				t.Fatal("denied callback invoked")
				return nil
			})
			if !errors.Is(err, authorization.ErrDenied) {
				t.Fatal("denial read labels or lost isolation", err)
			}
		})
	}
}

func TestP2PostgresResourceConsentRejectsUnsafeRuntimePrivileges(t *testing.T) {
	for _, change := range []string{
		`GRANT UPDATE(actions) ON mayi_resource.permissions TO mayi_p1_runtime`,
		`GRANT INSERT ON mayi_resource.permissions TO mayi_p1_runtime`,
		`GRANT TRUNCATE ON mayi_resource.labels TO mayi_p1_runtime`,
		`GRANT CREATE ON SCHEMA mayi_resource TO mayi_p1_runtime`,
		`ALTER TABLE mayi_resource.permissions DISABLE TRIGGER permission_changed`,
		`ALTER TABLE mayi_resource.labels NO FORCE ROW LEVEL SECURITY`,
	} {
		t.Run(change, func(t *testing.T) {
			e, a, _ := postgresConsentFixture(t)
			if _, err := e.admin.Exec(context.Background(), change); err != nil {
				t.Fatal(err)
			}
			if err := a.Check(context.Background()); !errors.Is(err, authorization.ErrUnavailable) {
				t.Fatal("unsafe resource contract accepted", err)
			}
		})
	}
}
