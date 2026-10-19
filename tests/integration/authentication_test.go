package integration_test

import (
	"context"
	"errors"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/domain/identity"
	"github.com/startificial/mayi/internal/services/authentication"
	"github.com/startificial/mayi/internal/services/authorization"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type upstreamProbe struct {
	calls           atomic.Int32
	afterExchange   func()
	fingerprint     string
	authenticatedAt time.Time
}

func (*upstreamProbe) ID() string { return "upstream" }
func (p *upstreamProbe) Fingerprint() string {
	if p.fingerprint != "" {
		return p.fingerprint
	}
	return strings.Repeat("a", 64)
}
func (*upstreamProbe) AuthorizationURL(string, string, string) (string, error) {
	return "https://idp.example/authorize", nil
}
func (p *upstreamProbe) Authenticate(context.Context, string, string, string, time.Time) (identity.Assertion, error) {
	p.calls.Add(1)
	if p.afterExchange != nil {
		p.afterExchange()
	}
	at := p.authenticatedAt
	if at.IsZero() {
		at = time.Now()
	}
	return identity.Assertion{Issuer: "https://idp.example", Subject: "upstream-alice", AuthenticatedAt: at}, nil
}
func loginAttempt(t *testing.T, e *foundation, consent *authorization.Service, p authorization.AccessProof, provider *upstreamProbe) (*authentication.Service, authentication.Callback) {
	t.Helper()
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.external_identities VALUES('a','upstream','https://idp.example','upstream-alice','user:alice') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	admission, err := authentication.NewAdmission(e.store, authentication.DefaultBudgetRules())
	if err != nil {
		t.Fatal(err)
	}
	service, err := authentication.New(e.store, clock{}, cryptoadapter.NewLoginSecrets(), provider, p.TenantIssuer, admission)
	if err != nil {
		t.Fatal(err)
	}
	var expires time.Time
	if err := e.admin.QueryRow(ctx, `SELECT expires_at FROM mayi.authorization_transactions WHERE tenant_id='a' AND handle_hash=$1`, p.AuthorizationHash).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Start(ctx, authentication.Start{BrowserHash: p.BrowserBindingHash, AuthorizationHash: p.AuthorizationHash, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	return service, authentication.Callback{State: challenge.State, Nonce: challenge.Nonce, Verifier: challenge.Verifier, Code: "upstream-code", BrowserHash: p.BrowserBindingHash, AuthorizationHash: p.AuthorizationHash, CreatedAt: challenge.CreatedAt, ExpiresAt: challenge.ExpiresAt}
}
func TestP2LoginDeniesForeignAndAlteredCorrelationBeforeExchange(t *testing.T) {
	e, consent, request, base := setupAuthorization(t)
	for _, mode := range []string{"state", "nonce", "verifier", "browser", "authorization", "time", "provider configuration"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := beginAuthorization(t, consent, request, base)
			provider := &upstreamProbe{}
			service, cb := loginAttempt(t, e, consent, p, provider)
			switch mode {
			case "state":
				cb.State = strings.Repeat("s", 43)
			case "nonce":
				cb.Nonce = strings.Repeat("n", 43)
			case "verifier":
				cb.Verifier = strings.Repeat("v", 43)
			case "browser":
				cb.BrowserHash = secretHash("foreign-browser")
			case "authorization":
				cb.AuthorizationHash = secretHash("foreign-workflow")
			case "time":
				cb.CreatedAt = cb.CreatedAt.Add(time.Second)
			case "provider configuration":
				provider.fingerprint = strings.Repeat("b", 64)
			}
			result, err := service.Complete(context.Background(), cb)
			if !errors.Is(err, authentication.ErrDenied) || result.Handle != "" || provider.calls.Load() != 0 {
				t.Fatal("correlation failure reached upstream or session", err, provider.calls.Load())
			}
		})
	}
}
func TestP2ConcurrentLoginHasOneSessionAndRotationEndsOldHandle(t *testing.T) {
	e, consent, request, base := setupAuthorization(t)
	p, _ := beginAuthorization(t, consent, request, base)
	provider := &upstreamProbe{}
	service, cb := loginAttempt(t, e, consent, p, provider)
	results := make(chan authentication.Session, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() { r, err := service.Complete(context.Background(), cb); results <- r; errs <- err }()
	}
	var handle string
	wins, denials := 0, 0
	for range 2 {
		r := <-results
		err := <-errs
		if err == nil {
			wins++
			if r.Handle != "" {
				handle = r.Handle
			}
		} else if errors.Is(err, authentication.ErrDenied) {
			denials++
		} else {
			t.Fatal(err)
		}
		if r.Handle != "" {
			handle = r.Handle
		}
	}
	if wins != 1 || denials != 1 || handle == "" || provider.calls.Load() != 1 {
		t.Fatal("login race", wins, denials, provider.calls.Load())
	}
	p, _ = beginAuthorization(t, consent, request, base)
	service, cb = loginAttempt(t, e, consent, p, provider)
	cb.PreviousSessionHash = secretHash(handle)
	rotated, err := service.Complete(context.Background(), cb)
	if err != nil || rotated.Handle == handle || rotated.Handle == "" {
		t.Fatal("session rotation", err)
	}
	var revoked bool
	if err := e.admin.QueryRow(context.Background(), `SELECT revoked FROM mayi.browser_sessions WHERE tenant_id='a' AND session_hash=$1`, secretHash(handle)).Scan(&revoked); err != nil || !revoked {
		t.Fatal("previous session survived authentication", err)
	}
	if err := service.End(context.Background(), secretHash(rotated.Handle), secretHash("foreign-browser")); !errors.Is(err, authentication.ErrDenied) {
		t.Fatal("foreign browser ended session", err)
	}
	if err := service.End(context.Background(), secretHash(rotated.Handle), base.BrowserBindingHash); err != nil {
		t.Fatal("session termination", err)
	}
	p.SessionHash = secretHash(rotated.Handle)
	if _, err := consent.PrepareConsent(context.Background(), p); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("ended session consent", err)
	}
}
func TestP2MembershipLossAndUnmappedIdentityNeverCreateSession(t *testing.T) {
	for _, mode := range []string{"membership removed", "mapping removed", "foreign tenant mapping"} {
		t.Run(mode, func(t *testing.T) {
			e, consent, request, base := setupAuthorization(t)
			p, _ := beginAuthorization(t, consent, request, base)
			provider := &upstreamProbe{}
			service, cb := loginAttempt(t, e, consent, p, provider)
			provider.afterExchange = func() {
				sql := `UPDATE mayi.principal_memberships SET active=false WHERE tenant_id='a'`
				if mode != "membership removed" {
					sql = `DELETE FROM mayi.external_identities WHERE tenant_id='a'`
				}
				if _, err := e.admin.Exec(context.Background(), sql); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "foreign tenant mapping" {
				if _, err := e.admin.Exec(context.Background(), `INSERT INTO mayi.external_identities VALUES('b','upstream','https://idp.example','upstream-alice','user:alice')`); err != nil {
					t.Fatal(err)
				}
			}
			result, err := service.Complete(context.Background(), cb)
			if !errors.Is(err, authentication.ErrDenied) || result.Handle != "" {
				t.Fatal("unauthorized identity got session", err)
			}
			var count int
			if err := e.admin.QueryRow(context.Background(), `SELECT count(*) FROM mayi.audit_events WHERE event_type='session_authenticated'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied login committed audit/session", err, count)
			}
		})
	}
}
func TestP2SessionAuditFailureRollsBackIssuanceButConsumesLoginAttempt(t *testing.T) {
	e, consent, request, base := setupAuthorization(t)
	p, _ := beginAuthorization(t, consent, request, base)
	provider := &upstreamProbe{}
	service, cb := loginAttempt(t, e, consent, p, provider)
	if _, err := e.admin.Exec(context.Background(), `CREATE FUNCTION mayi.fail_login_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_type='session_authenticated' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_login BEFORE INSERT ON mayi.audit_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_login_audit()`); err != nil {
		t.Fatal(err)
	}
	result, err := service.Complete(context.Background(), cb)
	if !errors.Is(err, authentication.ErrUnavailable) || result.Handle != "" {
		t.Fatal("uncommitted session returned", err)
	}
	var sessions int
	var claimed, completed bool
	if err := e.admin.QueryRow(context.Background(), `SELECT claimed_at IS NOT NULL,completed_at IS NOT NULL,(SELECT count(*) FROM mayi.browser_sessions) FROM mayi.login_attempts WHERE tenant_id='a' AND state_hash=$1`, secretHash(cb.State)).Scan(&claimed, &completed, &sessions); err != nil || !claimed || completed || sessions != 2 {
		t.Fatal("partial session commit", claimed, completed, sessions, err)
	}
	if _, err := service.Complete(context.Background(), cb); !errors.Is(err, authentication.ErrDenied) || provider.calls.Load() != 1 {
		t.Fatal("failed exchange attempt replayed", err)
	}
}

func TestP2StolenSessionCannotAuthorizeAnotherBrowserWorkflow(t *testing.T) {
	e, consent, request, base := setupAuthorization(t)
	p, _ := beginAuthorization(t, consent, request, base)
	provider := &upstreamProbe{}
	service, cb := loginAttempt(t, e, consent, p, provider)
	session, err := service.Complete(context.Background(), cb)
	if err != nil {
		t.Fatal(err)
	}
	foreign := base
	foreign.BrowserBindingHash = secretHash("other-browser")
	foreign.SessionHash = secretHash(session.Handle)
	foreign, _ = beginAuthorization(t, consent, request, foreign)
	if _, err := consent.PrepareConsent(context.Background(), foreign); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("stolen session crossed browser binding", err)
	}
}

func TestP2LoginRejectsAuthenticationBeforeAttemptWithoutSessionEffects(t *testing.T) {
	e, consent, request, base := setupAuthorization(t)
	p, _ := beginAuthorization(t, consent, request, base)
	provider := &upstreamProbe{}
	service, cb := loginAttempt(t, e, consent, p, provider)
	provider.authenticatedAt = cb.CreatedAt.Add(-time.Minute)
	ctx := context.Background()
	var before int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.browser_sessions`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	result, err := service.Complete(ctx, cb)
	if !errors.Is(err, authentication.ErrDenied) || result.Handle != "" || provider.calls.Load() != 1 {
		t.Fatal("stale upstream authentication accepted", err, provider.calls.Load())
	}
	// The persistence boundary must enforce the same domain rule for a direct
	// caller; it cannot mint a session from the already claimed stale attempt.
	login := identity.Login{TenantIssuer: p.TenantIssuer, ProviderID: provider.ID(), ProviderHash: provider.Fingerprint(), StateHash: secretHash(cb.State), NonceHash: secretHash(cb.Nonce), VerifierHash: secretHash(cb.Verifier), BrowserHash: cb.BrowserHash, AuthorizationHash: cb.AuthorizationHash, CreatedAt: cb.CreatedAt, ExpiresAt: cb.ExpiresAt}
	evidence := identity.Assertion{Issuer: "https://idp.example", Subject: "upstream-alice", AuthenticatedAt: provider.authenticatedAt}
	if err := e.store.CompleteLogin(ctx, login, evidence, secretHash("denied-session"), "", time.Now()); !errors.Is(err, authentication.ErrDenied) {
		t.Fatal("adapter accepted stale authentication", err)
	}
	var after, audits int
	var claimed, completed bool
	if err := e.admin.QueryRow(ctx, `SELECT claimed_at IS NOT NULL,completed_at IS NOT NULL,(SELECT count(*) FROM mayi.browser_sessions),(SELECT count(*) FROM mayi.audit_events WHERE event_type='session_authenticated') FROM mayi.login_attempts WHERE tenant_id='a' AND state_hash=$1`, secretHash(cb.State)).Scan(&claimed, &completed, &after, &audits); err != nil || !claimed || completed || after != before || audits != 0 {
		t.Fatal("stale authentication changed session state", claimed, completed, before, after, audits, err)
	}
	if _, err := service.Complete(ctx, cb); !errors.Is(err, authentication.ErrDenied) || provider.calls.Load() != 1 {
		t.Fatal("stale attempt replayed upstream exchange", err)
	}
}

func TestP2InactiveMemberCanEndOnlyTheirBrowserBoundSession(t *testing.T) {
	e, consent, request, base := setupAuthorization(t)
	p, _ := beginAuthorization(t, consent, request, base)
	provider := &upstreamProbe{}
	service, cb := loginAttempt(t, e, consent, p, provider)
	session, err := service.Complete(context.Background(), cb)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `UPDATE mayi.principal_memberships SET active=false WHERE tenant_id='a' AND subject='user:alice'`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"foreign browser", "foreign tenant session"} {
		t.Run(mode, func(t *testing.T) {
			hash, browser := secretHash(session.Handle), base.BrowserBindingHash
			if mode == "foreign browser" {
				browser = secretHash("another-browser")
			} else {
				hash = secretHash("session-b")
				browser = secretHash("browser-b")
			}
			if err := service.End(ctx, hash, browser); !errors.Is(err, authentication.ErrDenied) {
				t.Fatal("foreign session termination accepted", err)
			}
		})
	}
	var foreignRevoked bool
	var foreignAudits int
	if err := e.admin.QueryRow(ctx, `SELECT revoked,(SELECT count(*) FROM mayi.audit_events WHERE tenant_id='b' AND event_type='session_ended') FROM mayi.browser_sessions WHERE tenant_id='b' AND session_hash=$1`, secretHash("session-b")).Scan(&foreignRevoked, &foreignAudits); err != nil || foreignRevoked || foreignAudits != 0 {
		t.Fatal("denied termination changed foreign tenant", foreignRevoked, foreignAudits, err)
	}
	if err := service.End(ctx, secretHash(session.Handle), base.BrowserBindingHash); err != nil {
		t.Fatal("inactive membership prevented session termination", err)
	}
	var revoked bool
	var audits int
	if err := e.admin.QueryRow(ctx, `SELECT revoked,(SELECT count(*) FROM mayi.audit_events WHERE tenant_id='a' AND event_type='session_ended') FROM mayi.browser_sessions WHERE tenant_id='a' AND session_hash=$1`, secretHash(session.Handle)).Scan(&revoked, &audits); err != nil || !revoked || audits != 1 {
		t.Fatal("session termination did not commit", revoked, audits, err)
	}
	if _, err := e.admin.Exec(ctx, `UPDATE mayi.principal_memberships SET active=true WHERE tenant_id='a' AND subject='user:alice'`); err != nil {
		t.Fatal(err)
	}
	p.SessionHash = secretHash(session.Handle)
	if _, err := consent.PrepareConsent(ctx, p); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("reactivation revived ended session", err)
	}
}
