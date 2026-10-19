package integration_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/startificial/mayi/internal/app"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/services/authorization"
)

// This fixture is the RESOURCE OWNER, not a Mayi ACL cache or production
// adapter. Its own PostgreSQL rows authoritatively own permission/display state.
type fixtureConsentAuthority struct {
	e                             *foundation
	displayReads                  int
	beforeCallback, afterCallback func()
}

var _ authorization.ObjectConsentAuthority = (*fixtureConsentAuthority)(nil)

func (a *fixtureConsentAuthority) WithObjectConsent(ctx context.Context, q authorization.ObjectConsentQuery, fn func(domain.ObjectConsentProjection) error) error {
	tx, err := a.e.admin.Begin(ctx)
	if err != nil {
		return authorization.ErrUnavailable
	}
	defer tx.Rollback(ctx)
	c := q.Ceiling.Snapshot()
	if !q.Ceiling.BoundTo(q.TenantIssuer, c.Resource) {
		return authorization.ErrDenied
	}
	var version uint64
	// Read only decision metadata, for every tuple, before any object label.
	for _, d := range c.Details {
		var actions []string
		var v uint64
		if err := tx.QueryRow(ctx, `SELECT actions,version FROM consent_fixture.permissions WHERE tenant_id=$1 AND issuer=$2 AND subject=$3 AND resource=$4 AND type_uri=$5 AND identifier=$6 FOR SHARE`, q.TenantIssuer.TenantID, q.TenantIssuer.Issuer, q.Subject, c.Resource, d.Type, d.Identifier).Scan(&actions, &v); err != nil {
			return authorization.ErrDenied
		}
		for _, action := range d.Actions {
			if !slices.Contains(actions, action) {
				return authorization.ErrDenied
			}
		}
		if version != 0 && version != v {
			return authorization.ErrDenied
		}
		version = v
	}
	s := domain.ObjectConsentSpec{AuthorizationHash: q.AuthorizationHash, ClientID: q.ClientID, Subject: q.Subject, PermissionVersion: version, Ceiling: q.Ceiling}
	for _, d := range c.Details {
		o := domain.ConsentObject{Type: d.Type, Identifier: d.Identifier}
		if err := tx.QueryRow(ctx, `SELECT name FROM consent_fixture.labels WHERE tenant_id=$1 AND resource=$2 AND type_uri=$3 AND identifier=$4 FOR SHARE`, q.TenantIssuer.TenantID, c.Resource, d.Type, d.Identifier).Scan(&o.Name); err != nil {
			return authorization.ErrDenied
		}
		a.displayReads++
		s.Objects = append(s.Objects, o)
	}
	projection, err := domain.NewObjectConsentProjection(s)
	if err != nil {
		return authorization.ErrDenied
	}
	if a.beforeCallback != nil {
		a.beforeCallback()
	}
	err = fn(projection)
	if a.afterCallback != nil {
		a.afterCallback()
	}
	return err
}

func objectConsentFixture(t *testing.T) (*foundation, *authorization.Service, authorization.AccessProof, *fixtureConsentAuthority) {
	t.Helper()
	e, svc, _, proof, _ := setupPushed(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `CREATE SCHEMA consent_fixture;
 CREATE TABLE consent_fixture.permissions(tenant_id text,issuer text,subject text,resource text,type_uri text,identifier text,actions text[],version bigint,PRIMARY KEY(tenant_id,resource,type_uri,identifier,subject));
 CREATE TABLE consent_fixture.labels(tenant_id text,resource text,type_uri text,identifier text,name text,PRIMARY KEY(tenant_id,resource,type_uri,identifier));
 INSERT INTO consent_fixture.permissions VALUES('a','https://auth.example/t/a','user:alice','https://api.example','https://api.example/types/fixture/v1','workflow:123',ARRAY['read','write'],7),('a','https://auth.example/t/a','user:alice','https://api.example','https://api.example/types/fixture/v1','workflow:124',ARRAY['read'],7);
 INSERT INTO consent_fixture.labels VALUES('a','https://api.example','https://api.example/types/fixture/v1','workflow:123','Resource-owned <workflow>'),('a','https://api.example','https://api.example/types/fixture/v1','workflow:124','Unrequested secret title');`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.admin.Exec(context.Background(), `DROP SCHEMA consent_fixture CASCADE`) })
	begun, err := svc.BeginPushed(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	a := &fixtureConsentAuthority{e: e}
	svc, err = app.NewObjectAuthorization(e.store, clock{}, a)
	if err != nil {
		t.Fatal(err)
	}
	return e, svc, authorization.AccessProof{TenantIssuer: proof.TenantIssuer, SessionHash: secretHash("session-a"), BrowserBindingHash: proof.BrowserBindingHash, AuthorizationHash: secretHash(begun.Handle), CSRFHash: secretHash(begun.CSRFToken)}, a
}

func TestP2ObjectConsentUsesResourceGuardThroughSessionBindingCommit(t *testing.T) {
	e, svc, p, a := objectConsentFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.beforeCallback = func() {
		// NOWAIT proves the owner cannot change permission or display rows
		// while the resource guard spans Mayi's final authorization transaction.
		for _, table := range []string{"permissions", "labels"} {
			tx, err := e.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `SELECT * FROM consent_fixture.`+table+` WHERE identifier='workflow:123' FOR UPDATE NOWAIT`)
			var blocked *pgconn.PgError
			if !errors.As(err, &blocked) || blocked.Code != "55P03" {
				t.Fatal("resource metadata writer bypassed guard", err)
			}
			_ = tx.Rollback(ctx)
		}
	}
	a.afterCallback = func() {
		var bound bool
		if err := e.admin.QueryRow(ctx, `SELECT consent_session_hash=$2 FROM mayi.authorization_transactions WHERE tenant_id='a' AND handle_hash=$1`, p.AuthorizationHash, p.SessionHash).Scan(&bound); err != nil || !bound {
			t.Fatal("guard ended before Mayi commit", err)
		}
	}
	view, err := svc.PrepareConsent(ctx, p)
	if err != nil || view.DecisionAvailable || view.PermissionVersion != 7 || len(view.Objects) != 1 || view.Objects[0].Identifier != "workflow:123" || view.Objects[0].Name != "Resource-owned <workflow>" || len(view.Objects[0].Actions) != 1 || view.Objects[0].Actions[0].Name != "read" || a.displayReads != 1 {
		t.Fatal("resource display expanded request", view, err)
	}
	if out, err := svc.Decide(ctx, authorization.Decision{Proof: p, Approve: true}); !errors.Is(err, authorization.ErrDenied) || out.Code != "" {
		t.Fatal("display enabled object code issuance", err)
	}
	a.beforeCallback = nil
	a.afterCallback = nil
	if _, err := e.admin.Exec(ctx, `UPDATE consent_fixture.permissions SET actions=ARRAY['write'],version=8 WHERE identifier='workflow:123'`); err != nil {
		t.Fatal("guard not released", err)
	}
	if view, err := svc.PrepareConsent(ctx, p); !errors.Is(err, authorization.ErrDenied) || view.ClientID != "" || a.displayReads != 1 {
		t.Fatal("stale permission/display accepted", err)
	}
	var credentials int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.credentials`).Scan(&credentials); err != nil || credentials != 0 {
		t.Fatal("display issued credentials", err)
	}
}

func TestP2ObjectConsentRechecksSessionAndRollsBackDisplayBinding(t *testing.T) {
	for _, mode := range []string{"forbidden", "missing", "foreign owner", "session revoked", "audit failure"} {
		t.Run(mode, func(t *testing.T) {
			e, svc, p, a := objectConsentFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			switch mode {
			case "forbidden":
				if _, err := e.admin.Exec(ctx, `UPDATE consent_fixture.permissions SET actions=ARRAY['write'] WHERE identifier='workflow:123'`); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if _, err := e.admin.Exec(ctx, `DELETE FROM consent_fixture.permissions WHERE identifier='workflow:123'`); err != nil {
					t.Fatal(err)
				}
			case "foreign owner":
				if _, err := e.admin.Exec(ctx, `UPDATE consent_fixture.permissions SET tenant_id='b'`); err != nil {
					t.Fatal(err)
				}
			case "session revoked":
				a.beforeCallback = func() {
					if _, err := e.admin.Exec(ctx, `BEGIN; SELECT tenant_id FROM mayi.tenants WHERE tenant_id='a' FOR UPDATE; UPDATE mayi.browser_sessions SET revoked=true WHERE tenant_id='a'; COMMIT`); err != nil {
						t.Fatal("Mayi transaction held during resource acquisition", err)
					}
				}
			case "audit failure":
				if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_object_consent() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private outbox failure'; END$$; CREATE TRIGGER fail_object_consent BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_object_consent()`); err != nil {
					t.Fatal(err)
				}
			}
			view, err := svc.PrepareConsent(ctx, p)
			want := authorization.ErrDenied
			if mode == "audit failure" {
				want = authorization.ErrUnavailable
			}
			if !errors.Is(err, want) || view.ClientID != "" || len(view.Objects) != 0 || view.PermissionVersion != 0 {
				t.Fatal("failed consent leaked display", err)
			}
			if (mode == "forbidden" || mode == "missing" || mode == "foreign owner") && a.displayReads != 0 {
				t.Fatal("denial loaded object labels")
			}
			var bound bool
			var audits int
			if err := e.admin.QueryRow(ctx, `SELECT consent_session_hash IS NOT NULL,(SELECT count(*) FROM mayi.audit_events WHERE event_type='consent_prepared') FROM mayi.authorization_transactions WHERE tenant_id='a' AND handle_hash=$1`, p.AuthorizationHash).Scan(&bound, &audits); err != nil || bound || audits != 0 {
				t.Fatal("failed consent committed partial binding", err)
			}
		})
	}
}
