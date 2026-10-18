package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/app"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authorization"
)

func secretHash(secret string) string {
	digest := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(digest[:])
}
func setupAuthorization(t *testing.T) (*foundation, *authorization.Service, domain.Request, authorization.AccessProof) {
	t.Helper()
	e := setupFoundationDatabase(t)
	ctx := context.Background()
	_, err := e.admin.Exec(ctx, `INSERT INTO mayi.tenants VALUES('a','https://auth.example/t/a',1),('b','https://auth.example/t/b',1);
 INSERT INTO mayi.tenant_policies VALUES('a',600,3600,false),('b',600,3600,false);
 INSERT INTO mayi.resources VALUES('a','api','https://api.example','Example API',300,false),('b','api','https://api.example','Other API',300,false);
 INSERT INTO mayi.resource_scopes VALUES('a','api','read','Read items'),('a','api','write','Write items'),('b','api','read','Read items');
 INSERT INTO mayi.clients(tenant_id,client_id,name,redirect_uris,access_token_seconds) VALUES('a','web','Example client',ARRAY['https://app.example/cb?provider=mayi'],300),('b','web','Other client',ARRAY['https://app.example/cb?provider=mayi'],300);
 INSERT INTO mayi.client_resources VALUES('a','web','api'),('b','web','api');
 INSERT INTO mayi.principal_memberships VALUES('a','user:alice',true),('b','user:alice',true);
`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.admin.Exec(ctx, `INSERT INTO mayi.browser_sessions VALUES('a',$1,'user:alice',clock_timestamp()+interval '1 hour',false),('b',$2,'user:alice',clock_timestamp()+interval '1 hour',false)`, secretHash("session-a"), secretHash("session-b"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := app.NewAuthorization(e.store, clock{})
	if err != nil {
		t.Fatal(err)
	}
	tenantIssuer := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	request := domain.Request{TenantIssuer: tenantIssuer, ClientID: "web", RedirectURI: "https://app.example/cb?provider=mayi", ResourceURI: "https://api.example", PKCEChallenge: challenge, PermissionScopes: []string{"read"}, State: "client-state"}
	proof := authorization.AccessProof{TenantIssuer: tenantIssuer, SessionHash: secretHash("session-a"), BrowserBindingHash: secretHash("browser-a")}
	return e, svc, request, proof
}
func beginAuthorization(t *testing.T, svc *authorization.Service, request domain.Request, p authorization.AccessProof) (authorization.AccessProof, authorization.BeginResult) {
	t.Helper()
	started, err := svc.Begin(context.Background(), request, p.BrowserBindingHash)
	if err != nil {
		t.Fatal(err)
	}
	p.AuthorizationHash = secretHash(started.Handle)
	p.CSRFHash = secretHash(started.CSRFToken)
	return p, started
}
func TestP2ConsentCreatesExactGrantRevisionAndBoundCodeAtomically(t *testing.T) {
	e, svc, request, p := setupAuthorization(t)
	p, started := beginAuthorization(t, svc, request, p)
	ctx := context.Background()
	view, err := svc.PrepareConsent(ctx, p)
	if err != nil || view.ClientName != "Example client" || len(view.PermissionScopes) != 1 || view.PermissionScopes[0].Name != "read" || view.RedirectURI != request.RedirectURI {
		t.Fatal(view, err)
	}
	result, err := svc.Decide(ctx, authorization.Decision{Approve: true, Proof: p})
	if err != nil || result.Code == "" || result.State != request.State || result.RedirectURI != request.RedirectURI {
		t.Fatal(result, err)
	}
	var hash, origin, authorizationHash, redirect, pkce, subject string
	var scopes []string
	var revision int
	var issued, expires time.Time
	err = e.admin.QueryRow(ctx, `SELECT c.hash,c.origin_code,c.authorization_hash,c.redirect_uri,c.pkce_challenge,g.subject,r.scopes,r.revision,c.issued_at,c.expires_at
 FROM mayi.credentials c JOIN mayi.grant_revisions r USING(tenant_id,grant_id,revision) JOIN mayi.grants g USING(tenant_id,grant_id)
 WHERE c.tenant_id='a' AND c.hash=$1`, secretHash(result.Code)).Scan(&hash, &origin, &authorizationHash, &redirect, &pkce, &subject, &scopes, &revision, &issued, &expires)
	if err != nil || hash == result.Code || hash != origin || authorizationHash != p.AuthorizationHash || redirect != request.RedirectURI || pkce != challenge || subject != "user:alice" || revision != 1 || strings.Join(scopes, " ") != "read" || expires.Sub(issued) != time.Minute {
		t.Fatal("code lost original authorization binding", err)
	}
	if err := cryptoadapter.New().VerifyS256(pkce, verifier); err != nil {
		t.Fatal("stored code cannot validate original verifier", err)
	}
	var count int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.audit_events a JOIN mayi.outbox_events o USING(tenant_id,event_id) WHERE a.tenant_id='a' AND a.event_type='authorization_approved' AND a.actor_id='user:alice'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("missing atomic audit/outbox", count, err)
	}
	for _, secret := range []string{started.Handle, started.CSRFToken, result.Code} {
		var leaked bool
		if err := e.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.authorization_transactions t WHERE row_to_json(t)::text LIKE '%'||$1||'%') OR EXISTS(SELECT 1 FROM mayi.audit_events a WHERE row_to_json(a)::text LIKE '%'||$1||'%')`, secret).Scan(&leaked); err != nil || leaked {
			t.Fatal("plaintext authorization secret persisted", err)
		}
	}
	if replay, err := svc.Decide(ctx, authorization.Decision{Approve: true, Proof: p}); !errors.Is(err, authorization.ErrDenied) || replay.Code != "" {
		t.Fatal("consent replay issued a code", err)
	}
	if _, err := e.admin.Exec(ctx, `UPDATE mayi.authorization_transactions SET permission_scopes=ARRAY['write'] WHERE tenant_id='a'`); err == nil {
		t.Fatal("approved request mutable as owner")
	}
}
func TestP2ConsentRejectsForeignBrowserCSRFSessionAndMembership(t *testing.T) {
	e, svc, request, base := setupAuthorization(t)
	ctx := context.Background()
	for _, mode := range []string{"foreign tenant", "foreign session", "wrong browser", "wrong csrf", "revoked session", "inactive membership", "disabled client", "policy changed", "expired transaction"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := beginAuthorization(t, svc, request, base)
			switch mode {
			case "foreign tenant":
				p.TenantIssuer = grants.Scope{TenantID: "b", Issuer: "https://auth.example/t/b"}
				p.SessionHash = secretHash("session-b")
			case "foreign session":
				p.SessionHash = secretHash("session-b")
			case "wrong browser":
				p.BrowserBindingHash = secretHash("browser-evil")
			case "wrong csrf":
				p.CSRFHash = secretHash("csrf-evil")
			case "revoked session":
				if _, err := e.admin.Exec(ctx, `UPDATE mayi.browser_sessions SET revoked=true WHERE tenant_id='a'`); err != nil {
					t.Fatal(err)
				}
				defer e.admin.Exec(ctx, `UPDATE mayi.browser_sessions SET revoked=false WHERE tenant_id='a'`)
			case "inactive membership":
				if _, err := e.admin.Exec(ctx, `UPDATE mayi.principal_memberships SET active=false WHERE tenant_id='a'`); err != nil {
					t.Fatal(err)
				}
				defer e.admin.Exec(ctx, `UPDATE mayi.principal_memberships SET active=true WHERE tenant_id='a'`)
			case "disabled client":
				if _, err := e.admin.Exec(ctx, `UPDATE mayi.clients SET enabled=false WHERE tenant_id='a'`); err != nil {
					t.Fatal(err)
				}
				defer e.admin.Exec(ctx, `UPDATE mayi.clients SET enabled=true WHERE tenant_id='a'`)
			case "policy changed":
				if _, err := e.admin.Exec(ctx, `UPDATE mayi.tenants SET policy_version=2 WHERE tenant_id='a'`); err != nil {
					t.Fatal(err)
				}
				defer e.admin.Exec(ctx, `UPDATE mayi.tenants SET policy_version=1 WHERE tenant_id='a'`)
			case "expired transaction":
				// Expiry is a clock decision; preserve immutable stored request bytes.
				future, _ := app.NewAuthorization(e.store, &testClock{time.Now().Add(6 * time.Minute)})
				result, err := future.Decide(ctx, authorization.Decision{Approve: true, Proof: p})
				if !errors.Is(err, authorization.ErrDenied) || result.Code != "" {
					t.Fatal("expired authorization accepted", err)
				}
				return
			}
			result, err := svc.Decide(ctx, authorization.Decision{Approve: true, Proof: p})
			if !errors.Is(err, authorization.ErrDenied) || result.Code != "" || result.RedirectURI != "" {
				t.Fatal("denied proof returned authority", result, err)
			}
		})
	}
	var count int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.grants`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied consent created grants", count, err)
	}
}
func TestP2ConcurrentConsentHasOneWinner(t *testing.T) {
	e, svc, request, p := setupAuthorization(t)
	p, _ = beginAuthorization(t, svc, request, p)
	ctx := context.Background()
	results := make(chan error, 2)
	for range 2 {
		go func() { _, err := svc.Decide(ctx, authorization.Decision{Approve: true, Proof: p}); results <- err }()
	}
	wins, denials := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			wins++
		} else if errors.Is(err, authorization.ErrDenied) {
			denials++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || denials != 1 {
		t.Fatal("concurrent consent did not serialize", wins, denials)
	}
	var grants, codes int
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.grants),(SELECT count(*) FROM mayi.credentials)`).Scan(&grants, &codes); err != nil || grants != 1 || codes != 1 {
		t.Fatal("duplicate authority", grants, codes, err)
	}
}
func TestP2OutboxFailureRollsBackGrantRevisionCodeAndDecision(t *testing.T) {
	e, svc, request, p := setupAuthorization(t)
	p, _ = beginAuthorization(t, svc, request, p)
	ctx := context.Background()
	if _, err := svc.PrepareConsent(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_consent_outbox() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test delivery failure'; END$$; CREATE TRIGGER fail_consent BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_consent_outbox()`); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Decide(ctx, authorization.Decision{Approve: true, Proof: p})
	if !errors.Is(err, authorization.ErrUnavailable) || result.Code != "" {
		t.Fatal("failed audit returned a code", err)
	}
	var status string
	var grants, revisions, codes int
	if err := e.admin.QueryRow(ctx, `SELECT status,(SELECT count(*) FROM mayi.grants),(SELECT count(*) FROM mayi.grant_revisions),(SELECT count(*) FROM mayi.credentials) FROM mayi.authorization_transactions WHERE tenant_id='a' AND handle_hash=$1`, p.AuthorizationHash).Scan(&status, &grants, &revisions, &codes); err != nil || status != domain.Pending || grants != 0 || revisions != 0 || codes != 0 {
		t.Fatal("partial consent commit", status, grants, revisions, codes, err)
	}
	if _, err := e.admin.Exec(ctx, `DROP TRIGGER fail_consent ON mayi.outbox_events`); err != nil {
		t.Fatal(err)
	}
	result, err = svc.Decide(ctx, authorization.Decision{Approve: true, Proof: p})
	if err != nil || result.Code == "" {
		t.Fatal("rolled-back consent not retryable", err)
	}
}
func TestP2DenialConsumesWorkflowWithoutMintingCredentials(t *testing.T) {
	e, svc, request, p := setupAuthorization(t)
	p, _ = beginAuthorization(t, svc, request, p)
	ctx := context.Background()
	result, err := svc.Decide(ctx, authorization.Decision{Proof: p})
	if err != nil || result.Code != "" || result.RedirectURI != request.RedirectURI {
		t.Fatal(result, err)
	}
	if _, err := svc.Decide(ctx, authorization.Decision{Approve: true, Proof: p}); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("denied workflow reopened", err)
	}
	var count int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denial minted credentials", err)
	}
	for _, sql := range []string{`INSERT INTO mayi.principal_memberships VALUES('a','user:attacker',true)`, `UPDATE mayi.browser_sessions SET subject='user:attacker'`, `UPDATE mayi.authorization_transactions SET resource_uri='https://evil.example'`} {
		if _, err := e.db.Exec(ctx, sql); err == nil {
			t.Fatal("runtime changed authentication/request authority", sql)
		}
	}
}

func TestP2ConsentCannotMoveToAnotherSession(t *testing.T) {
	e, svc, request, p := setupAuthorization(t)
	p, _ = beginAuthorization(t, svc, request, p)
	ctx := context.Background()
	if _, err := svc.PrepareConsent(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.browser_sessions VALUES('a',$1,'user:alice',clock_timestamp()+interval '1 hour',false)`, secretHash("replacement-session")); err != nil {
		t.Fatal(err)
	}
	p.SessionHash = secretHash("replacement-session")
	if result, err := svc.Decide(ctx, authorization.Decision{Approve: true, Proof: p}); !errors.Is(err, authorization.ErrDenied) || result.Code != "" {
		t.Fatal("consent transferred between sessions", err)
	}
}

// Identity updates must conflict with in-flight consent even through direct SQL.
func TestP2IdentityMutationUsesConsentCoordinationLock(t *testing.T) {
	e, _, request, _ := setupAuthorization(t)
	ctx := context.Background()
	err := e.store.RunAuthorization(ctx, request.TenantIssuer, func(authorization.Transaction) error {
		for _, table := range []string{"browser_sessions", "principal_memberships"} {
			tx, err := e.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='50ms'`); err != nil {
				t.Fatal(err)
			}
			column := "revoked"
			if table == "principal_memberships" {
				column = "active"
			}
			_, err = tx.Exec(ctx, `UPDATE mayi.`+table+` SET `+column+`=false WHERE tenant_id='a'`)
			_ = tx.Rollback(ctx)
			if err == nil {
				t.Fatal("identity changed during consent", table)
			}
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "55P03" {
				t.Fatal("expected coordination lock conflict", table, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `UPDATE mayi.browser_sessions SET revoked=true WHERE tenant_id='a'`); err != nil {
		t.Fatal("identity remained locked after commit", err)
	}
}

type consentStoreProbe struct {
	authorization.Store
	afterAuthorization func()
	protectedLoads     int
}
type consentTransactionProbe struct {
	authorization.Transaction
	parent *consentStoreProbe
}

func (p *consentStoreProbe) AuthorizeConsent(ctx context.Context, proof authorization.AccessProof, now time.Time) (authorization.Principal, error) {
	actor, err := p.Store.AuthorizeConsent(ctx, proof, now)
	if err == nil {
		p.afterAuthorization()
	}
	return actor, err
}
func (p *consentStoreProbe) RunAuthorization(ctx context.Context, tenantIssuer grants.Scope, fn func(authorization.Transaction) error) error {
	return p.Store.RunAuthorization(ctx, tenantIssuer, func(tx authorization.Transaction) error {
		return fn(&consentTransactionProbe{Transaction: tx, parent: p})
	})
}
func (p *consentTransactionProbe) Authorization(ctx context.Context, hash string) (domain.Transaction, error) {
	p.parent.protectedLoads++
	return p.Transaction.Authorization(ctx, hash)
}
func TestP2MembershipLossBetweenChecksNeverLoadsConsentPayload(t *testing.T) {
	e, _, request, p := setupAuthorization(t)
	ctx := context.Background()
	probe := &consentStoreProbe{Store: e.store, afterAuthorization: func() {
		if _, err := e.admin.Exec(ctx, `UPDATE mayi.principal_memberships SET active=false WHERE tenant_id='a'`); err != nil {
			t.Fatal(err)
		}
	}}
	service, err := app.NewAuthorization(probe, clock{})
	if err != nil {
		t.Fatal(err)
	}
	p, _ = beginAuthorization(t, service, request, p)
	if result, err := service.Decide(ctx, authorization.Decision{Approve: true, Proof: p}); !errors.Is(err, authorization.ErrDenied) || result.Code != "" {
		t.Fatal("stale authorization approved", err)
	}
	if probe.protectedLoads != 0 {
		t.Fatal("denied request loaded protected transaction payload")
	}
}
