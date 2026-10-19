package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/app"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	domaintokens "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/authorization"
	"github.com/startificial/mayi/internal/services/tokens"
)

// Seed a trusted adapter fixture, not a live RAR approval flow. Public/services
// still reject object requests until registration, PAR and ACL/display support.
func storedObjectWorkflow(t *testing.T) (*foundation, domain.Request, authorization.AccessProof) {
	t.Helper()
	e, _, request, proof := setupAuthorization(t)
	objects, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: request.TenantIssuer, Resource: request.ResourceURI, Details: []grants.ObjectDetail{
		{Type: "https://api.example/types/workflow/v1", Identifier: "workflow:123", Actions: []string{"read"}},
		{Type: "https://api.example/types/workflow/v1", Identifier: "workflow:124", Actions: []string{"execute"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	request.ObjectCeiling = objects
	proof.AuthorizationHash, proof.CSRFHash = secretHash("object-workflow"), secretHash("object-csrf")
	now := time.Now().UTC().Truncate(time.Microsecond)
	pushed, err := domain.NewPushed(domain.PushedSpec{ID: "object-par", ReferenceHash: secretHash("object-par"), Request: request, PolicyVersion: 1, CreatedAt: now, ExpiresAt: now.Add(domain.PushedLifetime)})
	if err != nil {
		t.Fatal(err)
	}
	next, w, err := pushed.Begin("object-workflow", proof.AuthorizationHash, proof.BrowserBindingHash, proof.CSRFHash, now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.store.RunAuthorization(ctx, request.TenantIssuer, func(tx authorization.Transaction) error {
		if err := tx.CreatePushed(ctx, pushed); err != nil {
			return err
		}
		if err := tx.AuthorizePushed(ctx, authorization.PushedProof{TenantIssuer: request.TenantIssuer, ClientID: request.ClientID, ReferenceHash: pushed.Snapshot().ReferenceHash, BrowserBindingHash: proof.BrowserBindingHash}, now); err != nil {
			return err
		}
		return tx.ConsumePushed(ctx, next, w, now)
	}); err != nil {
		t.Fatal(err)
	}
	principal, err := e.store.AuthorizeConsent(ctx, proof, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.RunAuthorization(ctx, proof.TenantIssuer, func(tx authorization.Transaction) error {
		if err := tx.RecheckConsent(ctx, proof, principal, time.Now()); err != nil {
			return err
		}
		bound, err := w.BindSession(proof.SessionHash, time.Now())
		if err != nil {
			return err
		}
		if err := tx.BindConsentSession(ctx, bound); err != nil {
			return err
		}
		return consentAuthorityFixture{}.WithObjectConsent(ctx, authorization.ObjectConsentQuery{TenantIssuer: proof.TenantIssuer, Subject: principal.Subject, ClientID: request.ClientID, AuthorizationHash: proof.AuthorizationHash, Ceiling: request.ObjectCeiling}, func(ctx context.Context, p domain.ObjectConsentProjection) error {
			return tx.RecordObjectPresentation(ctx, bound, p, time.Now())
		})
	}); err != nil {
		t.Fatal(err)
	}
	return e, request, proof
}

func completeStoredObject(ctx context.Context, e *foundation, p authorization.AccessProof, mutate func(*domain.Spec)) error {
	principal, err := e.store.AuthorizeConsent(ctx, p, time.Now())
	if err != nil {
		return err
	}
	return e.store.RunAuthorization(ctx, p.TenantIssuer, func(tx authorization.Transaction) error {
		if err := tx.RecheckConsent(ctx, p, principal, time.Now()); err != nil {
			return err
		}
		w, err := tx.Authorization(ctx, p.AuthorizationHash)
		if err != nil {
			return err
		}
		if mutate != nil {
			s := w.Snapshot()
			mutate(&s)
			w, err = domain.New(s)
			if err != nil {
				return err
			}
		}
		return consentAuthorityFixture{}.WithObjectConsent(ctx, authorization.ObjectConsentQuery{TenantIssuer: p.TenantIssuer, Subject: principal.Subject, ClientID: w.Snapshot().Request.ClientID, AuthorizationHash: p.AuthorizationHash, Ceiling: w.Snapshot().Request.ObjectCeiling}, func(ctx context.Context, fresh domain.ObjectConsentProjection) error {
			now := time.Now()
			presented, err := tx.AuthorizeObjectApproval(ctx, w, fresh, now)
			if err != nil {
				return err
			}
			completed, revision, err := w.ApproveObjects(presented, fresh, principal.Subject, "object-grant", secretHash("object-code"), now, time.Hour)
			if err != nil {
				return err
			}
			return tx.CompleteAuthorization(ctx, completed, revision, now)
		})
	})
}

func TestP2ObjectSnapshotsRoundTripAcrossAuthorizationRevisionAndCode(t *testing.T) {
	e, request, p := storedObjectWorkflow(t)
	ctx := context.Background()
	if err := e.store.RunAuthorization(ctx, request.TenantIssuer, func(tx authorization.Transaction) error {
		w, err := tx.Authorization(ctx, p.AuthorizationHash)
		if err != nil || !w.Snapshot().Request.ObjectCeiling.Equal(request.ObjectCeiling) {
			t.Fatal("workflow lost typed object authority", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	svc, err := app.NewAuthorization(e.store, clock{})
	if err != nil {
		t.Fatal(err)
	}
	if view, err := svc.PrepareConsent(ctx, p); !errors.Is(err, authorization.ErrDenied) || view.ClientID != "" {
		t.Fatal("scope-only consent exposed unsupported objects", err)
	}
	if err := completeStoredObject(ctx, e, p, nil); err != nil {
		t.Fatal(err)
	}
	var same bool
	err = e.admin.QueryRow(ctx, `SELECT w.object_ceiling=g.current_object_ceiling AND w.object_ceiling=r.object_ceiling AND w.object_ceiling=c.object_ceiling
 FROM mayi.authorization_transactions w JOIN mayi.grants g USING(tenant_id,grant_id)
 JOIN mayi.grant_revisions r USING(tenant_id,grant_id) JOIN mayi.credentials c ON c.tenant_id=w.tenant_id AND c.hash=w.code_hash
 WHERE w.tenant_id='a' AND w.handle_hash=$1`, p.AuthorizationHash).Scan(&same)
	if err != nil || !same {
		t.Fatal("atomic approval snapshots differ", err)
	}
	if err := e.store.Run(ctx, request.TenantIssuer, func(tx tokens.Transaction) error {
		c, err := tx.Credential(ctx, secretHash("object-code"))
		if err != nil || !c.ObjectBound {
			t.Fatal("credential authentication projection lost binding or loaded object payload", err)
		}
		state, err := tx.GrantRevision(ctx, c.GrantID, c.Revision)
		if err != nil || !state.Revision.Snapshot().ObjectCeiling.Equal(request.ObjectCeiling) || !state.CurrentObjectCeiling.Equal(request.ObjectCeiling) {
			t.Fatal("revision rehydration dropped object authority", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	foreign := grants.Scope{TenantID: "b", Issuer: "https://auth.example/t/b"}
	if err := e.store.Run(ctx, foreign, func(tx tokens.Transaction) error {
		_, err := tx.Credential(ctx, secretHash("object-code"))
		return err
	}); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("foreign tenant read object credential", err)
	}
	if err := e.store.RunAuthorization(ctx, foreign, func(tx authorization.Transaction) error {
		_, err := tx.Authorization(ctx, p.AuthorizationHash)
		return err
	}); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("foreign tenant read object request", err)
	}
	var count int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.audit_events a JOIN mayi.outbox_events o USING(tenant_id,event_id) WHERE a.tenant_id='a' AND a.event_type='authorization_approved'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("object approval lost atomic audit/outbox", err)
	}
}

func TestP2ObjectSnapshotsAreImmutableAndCannotBeDroppedFromLineage(t *testing.T) {
	e, _, p := storedObjectWorkflow(t)
	ctx := context.Background()
	if err := completeStoredObject(ctx, e, p, nil); err != nil {
		t.Fatal(err)
	}
	_, err := e.admin.Exec(ctx, `INSERT INTO mayi.refresh_families(tenant_id,family_id,grant_id,revision,origin_code,absolute_deadline,idle_seconds,object_ceiling)
 SELECT 'a','object-family',grant_id,revision,$1,clock_timestamp()+interval '1 hour',120,object_ceiling FROM mayi.grant_revisions WHERE tenant_id='a'`, secretHash("object-code"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.issuances(tenant_id,issuance_id,grant_id,revision,origin_code,source_credential,resource,scopes,expires_at,object_ceiling,token_hash)
 SELECT 'a','fixture-issuance',grant_id,revision,hash,hash,resource,ceiling_scopes,clock_timestamp()+interval '5 minutes',object_ceiling,'`+secretHash("fixture-issuance")+`' FROM mayi.credentials WHERE tenant_id='a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.grant_revisions(tenant_id,grant_id,revision,scopes,expires_at,object_ceiling)
 SELECT tenant_id,grant_id,2,scopes,expires_at,object_ceiling FROM mayi.grant_revisions WHERE tenant_id='a' AND revision=1`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"credentials", "refresh_families", "issuances"} {
		if _, err := e.admin.Exec(ctx, `UPDATE mayi.`+table+` SET revision=2 WHERE tenant_id='a'`); err == nil {
			t.Fatal("credential lineage moved to another existing revision", table)
		}
	}
	for _, table := range []string{"authorization_transactions", "grants", "grant_revisions", "credentials", "refresh_families", "issuances"} {
		column := "object_ceiling"
		if table == "grants" {
			column = "current_object_ceiling"
		}
		if _, err := e.admin.Exec(ctx, `UPDATE mayi.`+table+` SET `+column+`=NULL WHERE tenant_id='a'`); err == nil {
			t.Fatal("owner could drop object ceiling", table)
		}
	}
	for _, sql := range []string{
		`INSERT INTO mayi.grant_revisions(tenant_id,grant_id,revision,scopes,expires_at) SELECT tenant_id,grant_id,3,scopes,expires_at FROM mayi.grant_revisions WHERE tenant_id='a' AND revision=1`,
		`INSERT INTO mayi.credentials(tenant_id,hash,kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,origin_code,authorization_hash) SELECT tenant_id,'lost-object','authorization_code',grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,'lost-object',authorization_hash FROM mayi.credentials WHERE tenant_id='a'`,
		`INSERT INTO mayi.refresh_families(tenant_id,family_id,grant_id,revision,origin_code,absolute_deadline,idle_seconds) SELECT tenant_id,'lost-object',grant_id,revision,origin_code,absolute_deadline,idle_seconds FROM mayi.refresh_families WHERE tenant_id='a'`,
		`INSERT INTO mayi.issuances(tenant_id,issuance_id,grant_id,revision,origin_code,source_credential,resource,scopes,expires_at,token_hash) SELECT tenant_id,'lost-object',grant_id,revision,origin_code,source_credential,resource,scopes,expires_at,'` + secretHash("lost-object") + `' FROM mayi.issuances WHERE tenant_id='a'`,
	} {
		if _, err := e.admin.Exec(ctx, sql); err == nil {
			t.Fatal("object descendant lost restrictions", sql)
		}
	}
}

func TestP2ObjectApprovalRollbackAndConcurrentDecision(t *testing.T) {
	e, _, p := storedObjectWorkflow(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_object_outbox() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'fixture failure'; END$$;
 CREATE TRIGGER fail_object_outbox BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_object_outbox()`); err != nil {
		t.Fatal(err)
	}
	if err := completeStoredObject(ctx, e, p, nil); err == nil {
		t.Fatal("failed outbox accepted object approval")
	}
	var roots, revisions, codes int
	var status string
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.grants),(SELECT count(*) FROM mayi.grant_revisions),(SELECT count(*) FROM mayi.credentials),status FROM mayi.authorization_transactions WHERE tenant_id='a'`).Scan(&roots, &revisions, &codes, &status); err != nil || roots != 0 || revisions != 0 || codes != 0 || status != domain.Pending {
		t.Fatal("partial object approval survived rollback", err)
	}
	if _, err := e.admin.Exec(ctx, `DROP TRIGGER fail_object_outbox ON mayi.outbox_events`); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- completeStoredObject(ctx, e, p, nil) }()
	}
	wins := 0
	for range 2 {
		if err := <-results; err == nil {
			wins++
		} else if !errors.Is(err, authorization.ErrDenied) {
			t.Fatal("unexpected concurrent decision failure", err)
		}
	}
	if wins != 1 {
		t.Fatal("object approval did not serialize", wins)
	}
}

func TestP2ObjectApprovalRejectsAReplacedSnapshot(t *testing.T) {
	e, request, p := storedObjectWorkflow(t)
	ctx := context.Background()
	err := completeStoredObject(ctx, e, p, func(s *domain.Spec) {
		objects := s.Request.ObjectCeiling.Snapshot()
		objects.Details[0].Actions = []string{"execute"}
		var err error
		s.Request.ObjectCeiling, err = grants.NewObjectCeiling(objects)
		if err != nil {
			t.Fatal(err)
		}
	})
	if !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("replacement snapshot approved", err)
	}
	var count int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.grants`).Scan(&count); err != nil || count != 0 {
		t.Fatal("replaced snapshot left partial authority", err)
	}
	if err := completeStoredObject(ctx, e, p, nil); err != nil {
		t.Fatal("unchanged original snapshot could not retry", request.ResourceURI, err)
	}
}

type objectIssuanceEffects struct{ calls int }

func (e *objectIssuanceEffects) SignAccessToken(context.Context, domaintokens.AccessClaims) (string, error) {
	e.calls++
	return "", errors.New("unexpected signing")
}
func (e *objectIssuanceEffects) NewMaterial(context.Context) (tokens.Material, error) {
	e.calls++
	return tokens.Material{}, errors.New("unexpected entropy")
}

func TestP2StoredObjectCodeDeniesScopeOnlyIssuanceAndPreservesReplayCutoff(t *testing.T) {
	e, request, p := storedObjectWorkflow(t)
	ctx := context.Background()
	if err := completeStoredObject(ctx, e, p, nil); err != nil {
		t.Fatal(err)
	}
	effects := &objectIssuanceEffects{}
	svc, err := app.NewIssuance(e.store, clock{}, effects, effects, e.store, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cmd := tokens.Command{Caller: tokens.Caller{Scope: request.TenantIssuer, ClientID: request.ClientID}, CredentialHash: secretHash("object-code"), Kind: tokens.AuthorizationCode, Resource: request.ResourceURI, Verifier: verifier, RedirectURI: request.RedirectURI}
	result, err := svc.Redeem(ctx, cmd)
	if !errors.Is(err, tokens.ErrInvalidCredential) || result.AccessToken != "" || effects.calls != 0 {
		t.Fatal("object code yielded a scope-only token", err)
	}
	var consumed bool
	if err := e.admin.QueryRow(ctx, `SELECT consumed FROM mayi.credentials WHERE tenant_id='a'`).Scan(&consumed); err != nil || consumed {
		t.Fatal("unsupported object code was consumed", err)
	}
	if _, err := e.admin.Exec(ctx, `UPDATE mayi.credentials SET consumed=true WHERE tenant_id='a'`); err != nil {
		t.Fatal(err)
	}
	result, err = svc.Redeem(ctx, cmd)
	if !errors.Is(err, tokens.ErrInvalidCredential) || result.AccessToken != "" || effects.calls != 0 {
		t.Fatal("object replay yielded a token", err)
	}
	var revoked bool
	if err := e.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.revoked_code_lineages WHERE tenant_id='a' AND origin_code=$1)`, cmd.CredentialHash).Scan(&revoked); err != nil || !revoked {
		t.Fatal("object code replay failed authoritative lineage cutoff", err)
	}
}

func TestP2CredentialAuthenticationDoesNotRehydrateObjectPayload(t *testing.T) {
	e, request, p := storedObjectWorkflow(t)
	ctx := context.Background()
	if err := completeStoredObject(ctx, e, p, nil); err != nil {
		t.Fatal(err)
	}
	// An owner-inserted malformed authority body must not be needed to check
	// client/PKCE possession. The closed path reads only its presence, then denies.
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.credentials(tenant_id,hash,kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,origin_code,pkce_challenge,redirect_uri,authorization_hash,object_ceiling)
 SELECT tenant_id,'malformed-object-code',kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,'malformed-object-code',pkce_challenge,redirect_uri,authorization_hash,
 jsonb_set(object_ceiling,'{details,0,identifier}','false'::jsonb) FROM mayi.credentials WHERE tenant_id='a'`); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Run(ctx, request.TenantIssuer, func(tx tokens.Transaction) error {
		c, err := tx.Credential(ctx, "malformed-object-code")
		if err != nil || !c.ObjectBound {
			t.Fatal("authentication lookup decoded object payload", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	effects := &objectIssuanceEffects{}
	svc, err := app.NewIssuance(e.store, clock{}, effects, effects, e.store, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, proof := range []string{"incorrect-verifier", verifier} {
		r, err := svc.Redeem(ctx, tokens.Command{Caller: tokens.Caller{Scope: request.TenantIssuer, ClientID: request.ClientID}, CredentialHash: "malformed-object-code", Kind: tokens.AuthorizationCode, Resource: request.ResourceURI, Verifier: proof, RedirectURI: request.RedirectURI})
		if !errors.Is(err, tokens.ErrInvalidCredential) || r.AccessToken != "" || effects.calls != 0 {
			t.Fatal("malformed object authority reached issuance", err)
		}
	}
}

func (*objectIssuanceEffects) DigestAccessToken(raw string) string { return raw }
