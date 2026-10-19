package integration_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/app"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authorization"
)

func setupPushed(t *testing.T) (*foundation, *authorization.Service, domain.Request, authorization.PushedProof, authorization.PushedResult) {
	t.Helper()
	e, _, request, base := setupAuthorization(t)
	svc, err := app.NewAuthorization(e.store, clock{})
	if err != nil {
		t.Fatal(err)
	}
	request.State = "pushed-client-state-at-least-16"
	request.ObjectCeiling, err = grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: request.TenantIssuer, Resource: request.ResourceURI, Details: []grants.ObjectDetail{{Type: "https://api.example/types/fixture/v1", Identifier: "workflow:123", Actions: []string{"read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	pushed, err := svc.Push(context.Background(), request)
	if err != nil || pushed.Reference == "" {
		t.Fatal("push", err)
	}
	proof := authorization.PushedProof{TenantIssuer: request.TenantIssuer, ClientID: request.ClientID, ReferenceHash: secretHash(pushed.Reference), BrowserBindingHash: base.BrowserBindingHash}
	return e, svc, request, proof, pushed
}

func TestP2PushedReferenceBindsExactWorkflowWithoutApprovingObjects(t *testing.T) {
	e, svc, request, proof, pushed := setupPushed(t)
	ctx := context.Background()
	var record string
	if err := e.admin.QueryRow(ctx, `SELECT to_jsonb(p)::text FROM mayi.pushed_requests p WHERE tenant_id='a' AND reference_hash=$1`, proof.ReferenceHash).Scan(&record); err != nil || strings.Contains(record, pushed.Reference) {
		t.Fatal("raw reference persisted or record missing", err)
	}
	out, err := svc.BeginPushed(ctx, proof)
	if err != nil || out.Handle == "" || out.CSRFToken == "" {
		t.Fatal("begin pushed", err)
	}
	var workflowHash, browserHash string
	var exact bool
	if err := e.admin.QueryRow(ctx, `SELECT p.authorization_hash,w.browser_binding_hash,p.object_ceiling=w.object_ceiling AND p.client_id=w.client_id AND p.redirect_uri=w.redirect_uri AND p.resource_uri=w.resource_uri AND p.permission_scopes=w.permission_scopes AND p.pkce_challenge=w.pkce_challenge AND p.binding_thumbprint=w.binding_thumbprint AND p.client_state=w.client_state AND p.policy_version=w.policy_version AND p.consumed_at=w.created_at
 FROM mayi.pushed_requests p JOIN mayi.authorization_transactions w ON w.tenant_id=p.tenant_id AND w.pushed_request_hash=p.reference_hash WHERE p.tenant_id='a' AND p.reference_hash=$1`, proof.ReferenceHash).Scan(&workflowHash, &browserHash, &exact); err != nil || !exact || workflowHash != secretHash(out.Handle) || browserHash != proof.BrowserBindingHash {
		t.Fatal("pushed/workflow snapshot mismatch", exact, err)
	}
	if replay, err := svc.BeginPushed(ctx, proof); !errors.Is(err, authorization.ErrDenied) || replay.Handle != "" {
		t.Fatal("reference replay accepted", err)
	}
	consent := authorization.AccessProof{TenantIssuer: request.TenantIssuer, SessionHash: secretHash("session-a"), AuthorizationHash: secretHash(out.Handle), BrowserBindingHash: proof.BrowserBindingHash, CSRFHash: secretHash(out.CSRFToken)}
	if view, err := svc.PrepareConsent(ctx, consent); !errors.Is(err, authorization.ErrDenied) || view.ClientID != "" {
		t.Fatal("PAR prematurely enabled object consent", err)
	}
	if result, err := svc.Decide(ctx, authorization.Decision{Proof: consent, Approve: true}); !errors.Is(err, authorization.ErrDenied) || result.Code != "" {
		t.Fatal("PAR issued object code before policy integration", err)
	}
	if direct, err := svc.Begin(ctx, request, proof.BrowserBindingHash); !errors.Is(err, authorization.ErrInvalid) || direct.Handle != "" {
		t.Fatal("direct typed bypass accepted", err)
	}
	var credentials int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.credentials`).Scan(&credentials); err != nil || credentials != 0 {
		t.Fatal("staged PAR issued credentials", credentials, err)
	}
}

func TestP2PushedDeniesSwappedExpiredAndChangedReferences(t *testing.T) {
	for _, mode := range []string{"foreign tenant", "foreign issuer", "wrong client", "unknown reference", "expired", "policy changed", "disabled client", "redirect changed"} {
		t.Run(mode, func(t *testing.T) {
			e, svc, _, proof, pushed := setupPushed(t)
			ctx := context.Background()
			switch mode {
			case "foreign tenant":
				proof.TenantIssuer.TenantID = "b"
				proof.TenantIssuer.Issuer = "https://auth.example/t/b"
			case "foreign issuer":
				proof.TenantIssuer.Issuer = "https://other.example/t/a"
			case "wrong client":
				proof.ClientID = "other-client"
			case "unknown reference":
				proof.ReferenceHash = secretHash("another-reference")
			case "expired":
				var err error
				svc, err = app.NewAuthorization(e.store, &testClock{pushed.ExpiresAt})
				if err != nil {
					t.Fatal(err)
				}
			case "policy changed", "disabled client", "redirect changed":
				query := `UPDATE mayi.tenants SET policy_version=policy_version+1 WHERE tenant_id='a'`
				if mode == "disabled client" {
					query = `UPDATE mayi.clients SET enabled=false WHERE tenant_id='a'`
				}
				if mode == "redirect changed" {
					query = `UPDATE mayi.clients SET redirect_uris=ARRAY['https://other.example/cb'] WHERE tenant_id='a'`
				}
				if _, err := e.admin.Exec(ctx, query); err != nil {
					t.Fatal(err)
				}
			}
			out, err := svc.BeginPushed(ctx, proof)
			if !errors.Is(err, authorization.ErrDenied) || out.Handle != "" || out.CSRFToken != "" {
				t.Fatal("invalid reference emitted workflow", mode, err)
			}
			var used bool
			var workflows int
			if err := e.admin.QueryRow(ctx, `SELECT consumed_at IS NOT NULL,(SELECT count(*) FROM mayi.authorization_transactions) FROM mayi.pushed_requests WHERE tenant_id='a'`).Scan(&used, &workflows); err != nil || used || workflows != 0 {
				t.Fatal("denial consumed reference or created workflow", mode, used, workflows, err)
			}
		})
	}
}

func TestP2PushedConsumptionRollbackAndConcurrentBrowserBinding(t *testing.T) {
	e, svc, _, proof, _ := setupPushed(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_pushed_use() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF EXISTS(SELECT 1 FROM mayi.audit_events WHERE event_id=NEW.event_id AND event_type='pushed_authorization_used') THEN RAISE EXCEPTION 'test outbox failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_pushed BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_pushed_use()`); err != nil {
		t.Fatal(err)
	}
	if out, err := svc.BeginPushed(ctx, proof); !errors.Is(err, authorization.ErrUnavailable) || out.Handle != "" || out.CSRFToken != "" {
		t.Fatal("uncommitted pushed workflow returned", err)
	}
	var used bool
	var workflows, audits int
	if err := e.admin.QueryRow(ctx, `SELECT consumed_at IS NOT NULL,(SELECT count(*) FROM mayi.authorization_transactions),(SELECT count(*) FROM mayi.audit_events) FROM mayi.pushed_requests WHERE tenant_id='a'`).Scan(&used, &workflows, &audits); err != nil || used || workflows != 0 || audits != 1 {
		t.Fatal("partial pushed use committed", used, workflows, audits, err)
	}
	if _, err := e.admin.Exec(ctx, `DROP TRIGGER fail_pushed ON mayi.outbox_events`); err != nil {
		t.Fatal(err)
	}
	type attempt struct {
		out   authorization.BeginResult
		proof authorization.PushedProof
		err   error
	}
	results := make(chan attempt, 2)
	for _, browser := range []string{proof.BrowserBindingHash, secretHash("other-browser")} {
		p := proof
		p.BrowserBindingHash = browser
		go func() { out, err := svc.BeginPushed(ctx, p); results <- attempt{out, p, err} }()
	}
	wins, denials := 0, 0
	for range 2 {
		r := <-results
		if r.err == nil {
			wins++
			var bound string
			if err := e.admin.QueryRow(ctx, `SELECT browser_binding_hash FROM mayi.authorization_transactions WHERE tenant_id='a' AND handle_hash=$1`, secretHash(r.out.Handle)).Scan(&bound); err != nil || bound != r.proof.BrowserBindingHash {
				t.Fatal("winner browser not pinned", err)
			}
		} else if errors.Is(r.err, authorization.ErrDenied) && r.out.Handle == "" {
			denials++
		} else {
			t.Fatal(r.err)
		}
	}
	if wins != 1 || denials != 1 {
		t.Fatal("pushed use race", wins, denials)
	}
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.audit_events a JOIN mayi.outbox_events o USING(tenant_id,event_id) WHERE a.tenant_id='a'`).Scan(&audits); err != nil || audits != 3 {
		t.Fatal("pushed use/audit atomicity", audits, err)
	}
}

func TestP2PushedStorageRejectsSnapshotReplacementAndHalfCommit(t *testing.T) {
	for _, mode := range []string{"replacement", "workflow only"} {
		t.Run(mode, func(t *testing.T) {
			e, _, _, proof, _ := setupPushed(t)
			ctx := context.Background()
			err := e.store.RunAuthorization(ctx, proof.TenantIssuer, func(tx authorization.Transaction) error {
				if _, err := tx.Pushed(ctx, proof.ReferenceHash); !errors.Is(err, authorization.ErrDenied) {
					t.Fatal("payload read before reference proof", err)
				}
				if err := tx.AuthorizePushed(ctx, proof, time.Now()); err != nil {
					return err
				}
				p, err := tx.Pushed(ctx, proof.ReferenceHash)
				if err != nil {
					return err
				}
				if mode == "replacement" {
					s := p.Snapshot()
					s.Request.State = "replacement-state-at-least-16"
					p, err = domain.NewPushed(s)
					if err != nil {
						return err
					}
				}
				now := time.Now()
				next, w, err := p.Begin("test-workflow", secretHash("test-handle"), proof.BrowserBindingHash, secretHash("test-csrf"), now)
				if err != nil {
					return err
				}
				if mode == "workflow only" {
					return tx.CreateAuthorization(ctx, w)
				}
				return tx.ConsumePushed(ctx, next, w, now)
			})
			if err == nil {
				t.Fatal("substituted snapshot or half-commit accepted")
			}
			var used bool
			var workflows int
			if err := e.admin.QueryRow(ctx, `SELECT consumed_at IS NOT NULL,(SELECT count(*) FROM mayi.authorization_transactions) FROM mayi.pushed_requests WHERE tenant_id='a'`).Scan(&used, &workflows); err != nil || used || workflows != 0 {
				t.Fatal("failed storage operation left partial state", err, used, workflows)
			}
		})
	}
}

func TestP2PushedSnapshotsAndConsumedProvenanceCannotBeRewritten(t *testing.T) {
	e, svc, _, proof, _ := setupPushed(t)
	ctx := context.Background()
	for _, query := range []string{
		`UPDATE mayi.pushed_requests SET client_state='substituted-state-at-least-16' WHERE tenant_id='a'`,
		`UPDATE mayi.pushed_requests SET object_ceiling=NULL WHERE tenant_id='a'`,
		`UPDATE mayi.pushed_requests SET expires_at=expires_at+interval '1 second' WHERE tenant_id='a'`,
		`DELETE FROM mayi.pushed_requests WHERE tenant_id='a'`,
	} {
		if _, err := e.admin.Exec(ctx, query); err == nil {
			t.Fatal("pushed snapshot/history mutated", query)
		}
	}
	out, err := svc.BeginPushed(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE mayi.pushed_requests SET consumed_at=NULL,authorization_hash=NULL WHERE tenant_id='a'`,
		`UPDATE mayi.authorization_transactions SET pushed_request_hash=NULL WHERE tenant_id='a'`,
	} {
		if _, err := e.admin.Exec(ctx, query); err == nil {
			t.Fatal("consumed provenance changed", query)
		}
	}
	err = e.store.RunAuthorization(ctx, proof.TenantIssuer, func(tx authorization.Transaction) error {
		// A fresh transaction cannot reuse the previous transaction's successful
		// reference proof to read the protected pushed payload.
		if _, err := tx.Pushed(ctx, proof.ReferenceHash); !errors.Is(err, authorization.ErrDenied) {
			t.Fatal("reference proof leaked across transactions", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var saved string
	if err := e.admin.QueryRow(ctx, `SELECT authorization_hash FROM mayi.pushed_requests WHERE tenant_id='a' AND reference_hash=$1`, proof.ReferenceHash).Scan(&saved); err != nil || saved != secretHash(out.Handle) {
		t.Fatal("consumed provenance lost", err)
	}
}

func TestP2PushedCreationAuditFailureReturnsNoReference(t *testing.T) {
	e, svc, request, _, _ := setupPushed(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_pushed_create() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test outbox failure'; END$$; CREATE TRIGGER fail_push BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_pushed_create()`); err != nil {
		t.Fatal(err)
	}
	if out, err := svc.Push(ctx, request); !errors.Is(err, authorization.ErrUnavailable) || out.Reference != "" || !out.ExpiresAt.IsZero() {
		t.Fatal("uncommitted push returned reference", err)
	}
	var records, audits int
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.pushed_requests),(SELECT count(*) FROM mayi.audit_events)`).Scan(&records, &audits); err != nil || records != 1 || audits != 1 {
		t.Fatal("failed push committed partial state", records, audits, err)
	}
}
