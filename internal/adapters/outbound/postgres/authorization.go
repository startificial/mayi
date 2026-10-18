package postgres

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authorization"
)

var _ authorization.Store = (*Store)(nil)

type authorizationTransaction struct {
	tx           pgx.Tx
	tenantIssuer grants.Scope
	version      uint64
	principal    *authorization.Principal
}

func (s *Store) RunAuthorization(ctx context.Context, tenantIssuer grants.Scope, fn func(authorization.Transaction) error) error {
	if !tenantIssuer.Valid() || fn == nil {
		return authorization.ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return authorization.ErrUnavailable
	}
	defer rollback(tx)
	if err := scopeTransaction(ctx, tx, tenantIssuer); err != nil {
		return authorization.ErrDenied
	}
	a := &authorizationTransaction{tx: tx, tenantIssuer: tenantIssuer}
	// Administrative policy mutations use FOR UPDATE on this same tenant row.
	if err := tx.QueryRow(ctx, `SELECT policy_version FROM mayi.tenants WHERE tenant_id=$1 AND issuer=$2 FOR SHARE`, tenantIssuer.TenantID, tenantIssuer.Issuer).Scan(&a.version); err != nil {
		return authorization.ErrDenied
	}
	if err := fn(a); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return authorization.ErrUnavailable
	}
	return nil
}
func (s *Store) AuthorizeConsent(ctx context.Context, p authorization.AccessProof, now time.Time) (authorization.Principal, error) {
	result := authorization.Principal{TenantIssuer: p.TenantIssuer, SessionHash: p.SessionHash}
	err := s.RunAuthorization(ctx, p.TenantIssuer, func(raw authorization.Transaction) error {
		a := raw.(*authorizationTransaction)
		// Only decision metadata is read. Request content and client/resource labels
		// cannot be loaded until session, tenant, membership and browser proof match.
		err := a.tx.QueryRow(ctx, `SELECT s.subject FROM mayi.browser_sessions s
 JOIN mayi.principal_memberships m USING(tenant_id,subject)
 JOIN mayi.authorization_transactions w ON w.tenant_id=s.tenant_id
 JOIN mayi.clients c ON c.tenant_id=w.tenant_id AND c.client_id=w.client_id AND c.enabled
 WHERE s.tenant_id=$1 AND s.session_hash=$2 AND NOT s.revoked AND s.expires_at>$6 AND s.expires_at>clock_timestamp() AND m.active
 AND EXISTS(SELECT 1 FROM mayi.session_authentication e WHERE e.tenant_id=s.tenant_id AND e.session_hash=s.session_hash AND e.browser_hash=$4)
 AND w.handle_hash=$3 AND w.browser_binding_hash=$4 AND ($5='' OR w.csrf_hash=$5)
 AND (w.consent_session_hash IS NULL OR w.consent_session_hash=s.session_hash) AND w.status='pending' AND w.policy_version=$7 AND w.created_at<=$6 AND w.expires_at>$6 AND w.expires_at>clock_timestamp()`, p.TenantIssuer.TenantID, p.SessionHash, p.AuthorizationHash, p.BrowserBindingHash, p.CSRFHash, now, a.version).Scan(&result.Subject)
		if err != nil {
			return authorization.ErrDenied
		}
		return nil
	})
	if err != nil {
		return authorization.Principal{}, err
	}
	return result, nil
}
func (a *authorizationTransaction) Registration(ctx context.Context, clientID, resourceURI string) (domain.Registration, error) {
	m := &management{tx: a.tx, scope: a.tenantIssuer, version: a.version}
	var r domain.Registration
	var err error
	// Pin enabled/redirect configuration through the final decision commit.
	var enabled bool
	if err := a.tx.QueryRow(ctx, `SELECT enabled FROM mayi.clients WHERE tenant_id=$1 AND client_id=$2 FOR SHARE`, a.tenantIssuer.TenantID, clientID).Scan(&enabled); err != nil || !enabled {
		return r, authorization.ErrInvalid
	}
	r.Client, err = m.Client(ctx, clientID)
	if err != nil {
		return r, authorization.ErrInvalid
	}
	var resourceID string
	if err := a.tx.QueryRow(ctx, `SELECT resource_id FROM mayi.resources WHERE tenant_id=$1 AND uri=$2 FOR SHARE`, a.tenantIssuer.TenantID, resourceURI).Scan(&resourceID); err != nil {
		return r, authorization.ErrInvalid
	}
	r.Resource, err = m.Resource(ctx, resourceID)
	if err != nil {
		return r, authorization.ErrInvalid
	}
	r.Policy, err = m.Policy(ctx)
	if err != nil {
		return r, authorization.ErrUnavailable
	}
	return r, nil
}
func (a *authorizationTransaction) CreateAuthorization(ctx context.Context, w domain.Transaction) error {
	s := w.Snapshot()
	if _, err := domain.New(s); err != nil || s.Request.TenantIssuer != a.tenantIssuer || s.Status != domain.Pending || s.PolicyVersion != a.version {
		return authorization.ErrInvalid
	}
	r := s.Request
	tag, err := a.tx.Exec(ctx, `INSERT INTO mayi.authorization_transactions(tenant_id,handle_hash,authorization_id,browser_binding_hash,csrf_hash,client_id,redirect_uri,resource_uri,permission_scopes,pkce_challenge,binding_thumbprint,client_state,policy_version,created_at,expires_at,status)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'pending' WHERE $15>clock_timestamp()`, a.tenantIssuer.TenantID, s.HandleHash, s.ID, s.BrowserBindingHash, s.CSRFHash, r.ClientID, r.RedirectURI, r.ResourceURI, r.PermissionScopes, r.PKCEChallenge, r.BindingThumbprint, r.State, s.PolicyVersion, s.CreatedAt, s.ExpiresAt)
	if err != nil || tag.RowsAffected() != 1 {
		return authorization.ErrUnavailable
	}
	_, err = a.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,object_ref) VALUES($1,'authorization_started',$2)`, a.tenantIssuer.TenantID, s.ID)
	return err
}
func (a *authorizationTransaction) Authorization(ctx context.Context, hash string) (domain.Transaction, error) {
	s := domain.Spec{}
	s.Request.TenantIssuer = a.tenantIssuer
	err := a.tx.QueryRow(ctx, `SELECT authorization_id,handle_hash,browser_binding_hash,csrf_hash,client_id,redirect_uri,resource_uri,permission_scopes,pkce_challenge,binding_thumbprint,client_state,policy_version,created_at,expires_at,status,COALESCE(subject,''),COALESCE(grant_id,''),COALESCE(code_hash,''),COALESCE(consent_session_hash,'')
 FROM mayi.authorization_transactions WHERE tenant_id=$1 AND handle_hash=$2 FOR UPDATE`, a.tenantIssuer.TenantID, hash).Scan(&s.ID, &s.HandleHash, &s.BrowserBindingHash, &s.CSRFHash, &s.Request.ClientID, &s.Request.RedirectURI, &s.Request.ResourceURI, &s.Request.PermissionScopes, &s.Request.PKCEChallenge, &s.Request.BindingThumbprint, &s.Request.State, &s.PolicyVersion, &s.CreatedAt, &s.ExpiresAt, &s.Status, &s.Subject, &s.GrantID, &s.CodeHash, &s.ConsentSessionHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Transaction{}, authorization.ErrDenied
		}
		return domain.Transaction{}, authorization.ErrUnavailable
	}
	w, err := domain.New(s)
	if err != nil {
		return domain.Transaction{}, authorization.ErrDenied
	}
	return w, nil
}
func (a *authorizationTransaction) RecheckConsent(ctx context.Context, proof authorization.AccessProof, p authorization.Principal, now time.Time) error {
	if p.TenantIssuer != a.tenantIssuer || proof.TenantIssuer != a.tenantIssuer || p.SessionHash != proof.SessionHash {
		return authorization.ErrDenied
	}
	var hash string
	err := a.tx.QueryRow(ctx, `SELECT w.handle_hash FROM mayi.authorization_transactions w
 JOIN mayi.browser_sessions s ON s.tenant_id=w.tenant_id
 JOIN mayi.principal_memberships m ON m.tenant_id=s.tenant_id AND m.subject=s.subject
 JOIN mayi.clients c ON c.tenant_id=w.tenant_id AND c.client_id=w.client_id
 WHERE w.tenant_id=$1 AND w.handle_hash=$2 AND w.browser_binding_hash=$3 AND ($4='' OR w.csrf_hash=$4)
 AND EXISTS(SELECT 1 FROM mayi.session_authentication e WHERE e.tenant_id=s.tenant_id AND e.session_hash=s.session_hash AND e.browser_hash=$3)
 AND w.status='pending' AND w.policy_version=$5 AND w.created_at<=$6 AND w.expires_at>$6 AND w.expires_at>clock_timestamp()
 AND (w.consent_session_hash IS NULL OR w.consent_session_hash=s.session_hash) AND s.session_hash=$7 AND s.subject=$8 AND NOT s.revoked AND s.expires_at>$6 AND s.expires_at>clock_timestamp() AND m.active AND c.enabled
 FOR UPDATE OF w FOR SHARE OF c`, a.tenantIssuer.TenantID, proof.AuthorizationHash, proof.BrowserBindingHash, proof.CSRFHash, a.version, now, p.SessionHash, p.Subject).Scan(&hash)
	if err != nil {
		return authorization.ErrDenied
	}
	a.principal = &p
	return nil
}
func (a *authorizationTransaction) CompleteAuthorization(ctx context.Context, w domain.Transaction, revision grants.Revision, now time.Time) error {
	s := w.Snapshot()
	r := s.Request
	if _, err := domain.New(s); err != nil || r.TenantIssuer != a.tenantIssuer || s.PolicyVersion != a.version || a.principal == nil || s.ConsentSessionHash != a.principal.SessionHash || (s.Status != domain.Approved && s.Status != domain.Denied) {
		return authorization.ErrDenied
	}
	event := "authorization_denied"
	if s.Status == domain.Approved {
		g := revision.Snapshot()
		if g.Scope != a.tenantIssuer || g.GrantID != s.GrantID || g.ClientID != r.ClientID || g.Subject != s.Subject || g.Resource != r.ResourceURI || g.Number != 1 || !slices.Equal(g.Scopes, r.PermissionScopes) || g.Subject != a.principal.Subject {
			return authorization.ErrDenied
		}
		if _, err := a.tx.Exec(ctx, `INSERT INTO mayi.grants(tenant_id,grant_id,client_id,subject,principal_type,resource,current_scopes,expires_at) VALUES($1,$2,$3,$4,'user',$5,$6,$7)`, a.tenantIssuer.TenantID, g.GrantID, g.ClientID, g.Subject, g.Resource, g.Scopes, g.ExpiresAt); err != nil {
			return err
		}
		if _, err := a.tx.Exec(ctx, `INSERT INTO mayi.grant_revisions(tenant_id,grant_id,revision,scopes,expires_at) VALUES($1,$2,1,$3,$4)`, a.tenantIssuer.TenantID, g.GrantID, g.Scopes, g.ExpiresAt); err != nil {
			return err
		}
		if _, err := a.tx.Exec(ctx, `INSERT INTO mayi.credentials(tenant_id,hash,kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,pkce_challenge,redirect_uri,binding_thumbprint,origin_code,authorization_hash)
 VALUES($1,$2,'authorization_code',$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$2,$12)`, a.tenantIssuer.TenantID, s.CodeHash, g.GrantID, g.Resource, g.ClientID, g.Scopes, now, now.Add(time.Minute), r.PKCEChallenge, r.RedirectURI, r.BindingThumbprint, s.HandleHash); err != nil {
			return err
		}
		event = "authorization_approved"
	}
	tag, err := a.tx.Exec(ctx, `UPDATE mayi.authorization_transactions SET status=$3,subject=NULLIF($4,''),grant_id=NULLIF($5,''),code_hash=NULLIF($6,''),decided_at=$7 WHERE tenant_id=$1 AND handle_hash=$2 AND status='pending' AND policy_version=$8 AND created_at<=$7 AND expires_at>$7 AND consent_session_hash=$9 AND expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM mayi.browser_sessions session JOIN mayi.principal_memberships membership USING(tenant_id,subject) WHERE session.tenant_id=$1 AND session.session_hash=$9 AND session.subject=$10 AND NOT session.revoked AND session.expires_at>clock_timestamp() AND membership.active)`, a.tenantIssuer.TenantID, s.HandleHash, s.Status, s.Subject, s.GrantID, s.CodeHash, now, a.version, a.principal.SessionHash, a.principal.Subject)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return authorization.ErrDenied
	}
	_, err = a.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id,object_ref,grant_id) VALUES($1,$2,$3,$4,NULLIF($5,''))`, a.tenantIssuer.TenantID, event, a.principal.Subject, s.ID, s.GrantID)
	return err
}

func (a *authorizationTransaction) BindConsentSession(ctx context.Context, w domain.Transaction) error {
	s := w.Snapshot()
	if a.principal == nil || s.Request.TenantIssuer != a.tenantIssuer || s.ConsentSessionHash != a.principal.SessionHash || s.Status != domain.Pending {
		return authorization.ErrDenied
	}
	tag, err := a.tx.Exec(ctx, `UPDATE mayi.authorization_transactions SET consent_session_hash=$3 WHERE tenant_id=$1 AND handle_hash=$2 AND consent_session_hash IS NULL AND status='pending' AND expires_at>clock_timestamp()`, a.tenantIssuer.TenantID, s.HandleHash, s.ConsentSessionHash)
	if err != nil {
		return authorization.ErrUnavailable
	}
	if tag.RowsAffected() != 1 {
		return authorization.ErrDenied
	}
	_, err = a.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id,object_ref) VALUES($1,'consent_prepared',$2,$3)`, a.tenantIssuer.TenantID, a.principal.Subject, s.ID)
	return err
}
