package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/startificial/mayi/internal/services/authorization"
)

func TestP2ObjectApprovalPersistsExactPresentationRevisionAndCodeUnderGuard(t *testing.T) {
	e, svc, p, a := objectConsentFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 2 {
		view, err := svc.PrepareConsent(ctx, p)
		if err != nil || !view.DecisionAvailable || view.PermissionVersion != 7 {
			t.Fatal("prepare exact display", err)
		}
	}
	var records, audits int
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.authorization_object_presentations),(SELECT count(*) FROM mayi.audit_events WHERE event_type='object_consent_presented')`).Scan(&records, &audits); err != nil || records != 1 || audits != 1 {
		t.Fatal("presentation was not idempotent", records, audits, err)
	}
	a.beforeCallback = func() {
		tx, err := e.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SELECT * FROM consent_fixture.permissions WHERE identifier='workflow:123' FOR UPDATE NOWAIT`)
		var blocked *pgconn.PgError
		if !errors.As(err, &blocked) || blocked.Code != "55P03" {
			t.Fatal("permission guard not held before approval", err)
		}
		_ = tx.Rollback(ctx)
	}
	a.afterCallback = func() {
		var committed bool
		if err := e.admin.QueryRow(ctx, `SELECT status='approved' AND EXISTS(SELECT 1 FROM mayi.credentials c WHERE c.tenant_id=w.tenant_id AND c.authorization_hash=w.handle_hash) FROM mayi.authorization_transactions w WHERE tenant_id='a' AND handle_hash=$1`, p.AuthorizationHash).Scan(&committed); err != nil || !committed {
			t.Fatal("resource guard ended before code commit", err)
		}
	}
	out, err := svc.Decide(ctx, authorization.Decision{Proof: p, Approve: true})
	if err != nil || out.Code == "" || out.RedirectURI == "" || out.State != "pushed-client-state-at-least-16" {
		t.Fatal("guarded approval", err)
	}
	var exact bool
	if err := e.admin.QueryRow(ctx, `SELECT p.permission_version=7 AND p.subject=g.subject AND p.session_hash=w.consent_session_hash AND p.object_ceiling=w.object_ceiling AND p.object_ceiling=g.current_object_ceiling AND p.object_ceiling=r.object_ceiling AND p.object_ceiling=c.object_ceiling AND c.origin_code=c.hash AND c.authorization_hash=w.handle_hash AND c.ceiling_scopes=w.permission_scopes AND c.pkce_challenge=w.pkce_challenge AND c.redirect_uri=w.redirect_uri AND c.expires_at=c.issued_at+interval '60 seconds'
 FROM mayi.authorization_object_presentations p JOIN mayi.authorization_transactions w USING(tenant_id,handle_hash)
 JOIN mayi.grants g ON g.tenant_id=w.tenant_id AND g.grant_id=w.grant_id
 JOIN mayi.grant_revisions r ON r.tenant_id=g.tenant_id AND r.grant_id=g.grant_id AND r.revision=1
 JOIN mayi.credentials c ON c.tenant_id=w.tenant_id AND c.hash=w.code_hash
 WHERE w.tenant_id='a' AND w.handle_hash=$1 AND c.hash=$2`, p.AuthorizationHash, secretHash(out.Code)).Scan(&exact); err != nil || !exact {
		t.Fatal("approved authority lost immutable presentation lineage", err)
	}
	a.beforeCallback = nil
	a.afterCallback = nil
	if replay, err := svc.Decide(ctx, authorization.Decision{Proof: p, Approve: true}); !errors.Is(err, authorization.ErrDenied) || replay.Code != "" {
		t.Fatal("approval replay emitted authority", err)
	}
}

func TestP2ObjectApprovalDeniesMissingOrChangedPresentationAndResourcePermission(t *testing.T) {
	for _, mode := range []string{"missing presentation", "permission version", "label changed", "permission removed", "foreign tenant", "foreign issuer", "wrong csrf", "session revoked during guard"} {
		t.Run(mode, func(t *testing.T) {
			e, svc, p, a := objectConsentFixture(t)
			ctx := context.Background()
			if mode != "missing presentation" {
				if _, err := svc.PrepareConsent(ctx, p); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "permission version":
				if _, err := e.admin.Exec(ctx, `UPDATE consent_fixture.permissions SET version=8 WHERE identifier='workflow:123'`); err != nil {
					t.Fatal(err)
				}
			case "label changed":
				if _, err := e.admin.Exec(ctx, `UPDATE consent_fixture.labels SET name='Changed title' WHERE identifier='workflow:123'`); err != nil {
					t.Fatal(err)
				}
			case "permission removed":
				if _, err := e.admin.Exec(ctx, `UPDATE consent_fixture.permissions SET actions=ARRAY['write'],version=8 WHERE identifier='workflow:123'`); err != nil {
					t.Fatal(err)
				}
			case "foreign tenant":
				p.TenantIssuer.TenantID = "b"
				p.TenantIssuer.Issuer = "https://auth.example/t/b"
			case "foreign issuer":
				p.TenantIssuer.Issuer = "https://other.example/t/a"
			case "wrong csrf":
				p.CSRFHash = secretHash("wrong-csrf")
			case "session revoked during guard":
				a.beforeCallback = func() {
					if _, err := e.admin.Exec(ctx, `BEGIN; SELECT tenant_id FROM mayi.tenants WHERE tenant_id='a' FOR UPDATE; UPDATE mayi.browser_sessions SET revoked=true WHERE tenant_id='a'; COMMIT`); err != nil {
						t.Fatal(err)
					}
				}
			}
			out, err := svc.Decide(ctx, authorization.Decision{Proof: p, Approve: true})
			if !errors.Is(err, authorization.ErrDenied) || out.Code != "" || out.RedirectURI != "" {
				t.Fatal("changed authority approved", err)
			}
			var credentials, grants int
			var pending bool
			if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.credentials),(SELECT count(*) FROM mayi.grants),status='pending' FROM mayi.authorization_transactions WHERE tenant_id='a'`).Scan(&credentials, &grants, &pending); err != nil || credentials != 0 || grants != 0 || !pending {
				t.Fatal("denial left authority or consumed workflow", err)
			}
			if mode == "permission version" || mode == "label changed" {
				if view, err := svc.PrepareConsent(ctx, p); !errors.Is(err, authorization.ErrDenied) || view.ClientID != "" {
					t.Fatal("first display was silently replaced", err)
				}
			}
		})
	}
}

func TestP2ObjectApprovalAuditRollbackAndConcurrentOneUse(t *testing.T) {
	e, svc, p, _ := objectConsentFixture(t)
	ctx := context.Background()
	if _, err := svc.PrepareConsent(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_object_approval() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_type='authorization_approved' THEN RAISE EXCEPTION 'private audit failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_object_approval BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_object_approval()`); err != nil {
		t.Fatal(err)
	}
	if out, err := svc.Decide(ctx, authorization.Decision{Proof: p, Approve: true}); !errors.Is(err, authorization.ErrUnavailable) || out.Code != "" {
		t.Fatal("uncommitted code returned", err)
	}
	var credentials, grants int
	var pending bool
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.credentials),(SELECT count(*) FROM mayi.grants),status='pending' FROM mayi.authorization_transactions WHERE tenant_id='a' AND handle_hash=$1`, p.AuthorizationHash).Scan(&credentials, &grants, &pending); err != nil || credentials != 0 || grants != 0 || !pending {
		t.Fatal("partial approval survived rollback", err)
	}
	if _, err := e.admin.Exec(ctx, `DROP TRIGGER fail_object_approval ON mayi.outbox_events`); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			out, err := svc.Decide(ctx, authorization.Decision{Proof: p, Approve: true})
			if err == nil && out.Code == "" {
				err = errors.New("winner returned no code")
			}
			if err != nil && out.Code != "" {
				err = errors.New("failure leaked code")
			}
			errs <- err
		}()
	}
	wins, denials := 0, 0
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			wins++
		case errors.Is(err, authorization.ErrDenied):
			denials++
		default:
			t.Fatal(err)
		}
	}
	if wins != 1 || denials != 1 {
		t.Fatal("concurrent approvals", wins, denials)
	}
	var audits int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.audit_events a JOIN mayi.outbox_events o USING(tenant_id,event_id) WHERE a.tenant_id='a' AND a.event_type='authorization_approved'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("approval audit not atomic", err)
	}
}

func TestP2ObjectPresentationCannotBeRewrittenOrUsedWithoutApprovalAuthorization(t *testing.T) {
	e, svc, p, _ := objectConsentFixture(t)
	ctx := context.Background()
	if _, err := svc.PrepareConsent(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{`UPDATE mayi.authorization_object_presentations SET permission_version=8`, `UPDATE mayi.authorization_object_presentations SET objects='[]'`, `DELETE FROM mayi.authorization_object_presentations`} {
		if _, err := e.admin.Exec(ctx, query); err == nil {
			t.Fatal("immutable presentation changed")
		}
	}
	actor, err := e.store.AuthorizeConsent(ctx, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = e.store.RunAuthorization(ctx, p.TenantIssuer, func(tx authorization.Transaction) error {
		if err := tx.RecheckConsent(ctx, p, actor, time.Now()); err != nil {
			return err
		}
		w, err := tx.Authorization(ctx, p.AuthorizationHash)
		if err != nil {
			return err
		}
		now := time.Now()
		done, revision, err := w.Decide(true, actor.Subject, "bypass-grant", secretHash("bypass-code"), now, time.Hour)
		if err != nil {
			return err
		}
		return tx.CompleteAuthorization(ctx, done, revision, now)
	})
	if !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("durable display bypassed fresh approval authorization", err)
	}
	read, err := e.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Rollback(ctx)
	if _, err := read.Exec(ctx, `SELECT set_config('mayi.tenant_id','b',true)`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := read.QueryRow(ctx, `SELECT count(*) FROM mayi.authorization_object_presentations WHERE tenant_id='a'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("foreign presentation visible", err)
	}
	_, err = read.Exec(ctx, `UPDATE mayi.authorization_object_presentations SET permission_version=permission_version`)
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("runtime has presentation rewrite privilege", err)
	}
}

func TestP2ObjectDenialDoesNotDependOnResourceAvailability(t *testing.T) {
	e, svc, p, _ := objectConsentFixture(t)
	ctx := context.Background()
	if _, err := svc.PrepareConsent(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `DROP SCHEMA consent_fixture CASCADE`); err != nil {
		t.Fatal(err)
	}
	out, err := svc.Decide(ctx, authorization.Decision{Proof: p, Approve: false})
	if err != nil || out.Code != "" || out.RedirectURI == "" {
		t.Fatal("denial depended on resource authority", err)
	}
	var terminal bool
	if err := e.admin.QueryRow(ctx, `SELECT status='denied' AND NOT EXISTS(SELECT 1 FROM mayi.credentials) FROM mayi.authorization_transactions WHERE tenant_id='a' AND handle_hash=$1`, p.AuthorizationHash).Scan(&terminal); err != nil || !terminal {
		t.Fatal("denial issued credential", err)
	}
}

func TestP2ObjectPresentationAuditFailureRollsBackEvidenceAndSessionBinding(t *testing.T) {
	e, svc, p, _ := objectConsentFixture(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_presentation_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_type='object_consent_presented' THEN RAISE EXCEPTION 'private presentation audit failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_presentation_audit BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_presentation_audit()`); err != nil {
		t.Fatal(err)
	}
	if view, err := svc.PrepareConsent(ctx, p); !errors.Is(err, authorization.ErrUnavailable) || view.ClientID != "" || view.DecisionAvailable {
		t.Fatal("uncommitted presentation disclosed", err)
	}
	var records, audits int
	var bound bool
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.authorization_object_presentations),(SELECT count(*) FROM mayi.audit_events WHERE event_type IN ('object_consent_presented','consent_prepared')),consent_session_hash IS NOT NULL FROM mayi.authorization_transactions WHERE tenant_id='a' AND handle_hash=$1`, p.AuthorizationHash).Scan(&records, &audits, &bound); err != nil || records != 0 || audits != 0 || bound {
		t.Fatal("partial presentation state committed", records, audits, bound, err)
	}
}
