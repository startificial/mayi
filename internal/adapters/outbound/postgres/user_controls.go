package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	domain "github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authentication"
	"github.com/startificial/mayi/internal/services/grants"
	"time"
)

var _ grants.Store = (*Store)(nil)
var _ grants.UserGrants = (*userGrants)(nil)
var _ authentication.SessionControlStore = (*Store)(nil)

type userGrants struct {
	tx         pgx.Tx
	scope      domain.Scope
	subject    string
	authorized string
}

func authenticatedSession(ctx context.Context, tx pgx.Tx, scope domain.Scope, session, browser string, now time.Time) (string, error) {
	var subject string
	err := tx.QueryRow(ctx, `SELECT s.subject FROM mayi.browser_sessions s JOIN mayi.session_authentication e USING(tenant_id,session_hash) JOIN mayi.principal_memberships m USING(tenant_id,subject) WHERE s.tenant_id=$1 AND s.session_hash=$2 AND e.browser_hash=$3 AND NOT s.revoked AND m.active AND s.expires_at>$4 AND s.expires_at>clock_timestamp() AND s.last_used_at>clock_timestamp()-interval '15 minutes' FOR UPDATE OF s`, scope.TenantID, session, browser, now).Scan(&subject)
	if err != nil {
		return "", authentication.ErrDenied
	}
	return subject, nil
}
func (s *Store) WithUserGrants(ctx context.Context, p grants.BrowserProof, now time.Time, fn func(grants.UserGrants) error) error {
	return s.authentication(ctx, p.Scope, func(tx pgx.Tx) error {
		subject, err := authenticatedSession(ctx, tx, p.Scope, p.SessionHash, p.BrowserHash, now)
		if err != nil {
			return grants.ErrDenied
		}
		return fn(&userGrants{tx: tx, scope: p.Scope, subject: subject})
	})
}
func (g *userGrants) List(ctx context.Context) ([]grants.Summary, error) {
	return listGrants(ctx, g.tx, g.scope, g.subject, "", 100)
}
func (s *Store) ListAdministrator(ctx context.Context, scope domain.Scope, after string, limit int) ([]grants.Summary, error) {
	var result []grants.Summary
	err := s.authentication(ctx, scope, func(tx pgx.Tx) error {
		var err error
		result, err = listGrants(ctx, tx, scope, "", after, limit)
		return err
	})
	return result, err
}
func listGrants(ctx context.Context, tx pgx.Tx, scope domain.Scope, subject, after string, limit int) ([]grants.Summary, error) {
	if limit < 1 || limit > 100 {
		return nil, grants.ErrDenied
	}
	rows, err := tx.Query(ctx, `SELECT g.grant_id,g.client_id,g.resource,g.subject,r.revision,r.scopes,r.object_ceiling,LEAST(g.expires_at,r.expires_at),usage.count,usage.last_issued,u.last_checked_at,COALESCE(u.token_checks,0)
 FROM mayi.grants g JOIN LATERAL(SELECT revision,scopes,object_ceiling,expires_at FROM mayi.grant_revisions WHERE tenant_id=g.tenant_id AND grant_id=g.grant_id ORDER BY revision DESC LIMIT 1) r ON true
 LEFT JOIN LATERAL(SELECT count(*) AS count,max(issued_at) AS last_issued FROM mayi.issuances WHERE tenant_id=g.tenant_id AND grant_id=g.grant_id) usage ON true
 LEFT JOIN mayi.grant_usage u ON u.tenant_id=g.tenant_id AND u.grant_id=g.grant_id
 WHERE g.tenant_id=$1 AND ($2='' OR g.subject=$2) AND g.grant_id>$3 AND NOT g.revoked AND g.expires_at>clock_timestamp() ORDER BY g.grant_id LIMIT $4`, scope.TenantID, subject, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []grants.Summary{}
	for rows.Next() {
		var item grants.Summary
		var objects []byte
		if err := rows.Scan(&item.ID, &item.ClientID, &item.Resource, &item.Subject, &item.Revision, &item.Scopes, &objects, &item.ExpiresAt, &item.TokensIssued, &item.LastIssuedAt, &item.LastUsedAt, &item.TokenChecks); err != nil {
			return nil, err
		}
		item.Objects, err = decodeObjectCeiling(objects, scope, item.Resource)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
func (g *userGrants) Owned(ctx context.Context, id string) (bool, error) {
	var ref string
	err := g.tx.QueryRow(ctx, `SELECT grant_id FROM mayi.grants WHERE tenant_id=$1 AND grant_id=$2 AND subject=$3 FOR UPDATE`, g.scope.TenantID, id, g.subject).Scan(&ref)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	g.authorized = ref
	return true, nil
}
func (g *userGrants) Revoke(ctx context.Context, id string) error {
	if g.authorized != id || id == "" {
		return grants.ErrDenied
	}
	if err := revokeGrant(ctx, g.tx, g.scope, id); err != nil {
		return err
	}
	_, err := g.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,grant_id,actor_id) VALUES($1,'user_grant_revoked',$2,$3)`, g.scope.TenantID, id, g.subject)
	return err
}
func (s *Store) RevokeAdministrator(ctx context.Context, scope domain.Scope, kind, id, actor string) error {
	return s.authentication(ctx, scope, func(tx pgx.Tx) error {
		// authentication holds the tenant write lock, excluding issuance/status and
		// other lifecycle mutations. Set-based updates bound application memory and
		// round trips while preserving one atomic incident cut-off.
		for _, query := range []string{
			`UPDATE mayi.grants SET revoked=true WHERE tenant_id=$1 AND (($2='grant' AND grant_id=$3) OR ($2='user' AND subject=$3) OR ($2='client' AND client_id=$3))`,
			`UPDATE mayi.refresh_families f SET revoked=true WHERE f.tenant_id=$1 AND EXISTS(SELECT 1 FROM mayi.grants g WHERE g.tenant_id=f.tenant_id AND g.grant_id=f.grant_id AND (($2='grant' AND g.grant_id=$3) OR ($2='user' AND g.subject=$3) OR ($2='client' AND g.client_id=$3)))`,
			`UPDATE mayi.issuances i SET revoked=true WHERE i.tenant_id=$1 AND EXISTS(SELECT 1 FROM mayi.grants g WHERE g.tenant_id=i.tenant_id AND g.grant_id=i.grant_id AND (($2='grant' AND g.grant_id=$3) OR ($2='user' AND g.subject=$3) OR ($2='client' AND g.client_id=$3)))`,
		} {
			if _, err := tx.Exec(ctx, query, scope.TenantID, kind, id); err != nil {
				return err
			}
		}

		_, err := tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id,object_ref) VALUES($1,'administrator_grants_revoked',$2,$3)`, scope.TenantID, actor, kind+":"+id)
		return err
	})
}
func (s *Store) ListSessions(ctx context.Context, p authentication.SessionProof, now time.Time) ([]authentication.SessionInfo, error) {
	var result []authentication.SessionInfo
	err := s.authentication(ctx, p.Scope, func(tx pgx.Tx) error {
		subject, err := authenticatedSession(ctx, tx, p.Scope, p.SessionHash, p.BrowserHash, now)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT session_hash,session_hash=$3,created_at,last_used_at,expires_at FROM mayi.browser_sessions WHERE tenant_id=$1 AND subject=$2 AND NOT revoked AND expires_at>clock_timestamp() AND last_used_at>clock_timestamp()-interval '15 minutes' ORDER BY created_at DESC LIMIT 101`, p.Scope.TenantID, subject, p.SessionHash)
		if err != nil {
			return err
		}
		defer rows.Close()
		result = []authentication.SessionInfo{}
		for rows.Next() {
			var item authentication.SessionInfo
			if err = rows.Scan(&item.Reference, &item.Current, &item.CreatedAt, &item.LastUsedAt, &item.ExpiresAt); err != nil {
				return err
			}
			result = append(result, item)
		}
		if len(result) > 100 {
			return authentication.ErrUnavailable
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (s *Store) RevokeSession(ctx context.Context, p authentication.SessionProof, id string, now time.Time) error {
	return s.authentication(ctx, p.Scope, func(tx pgx.Tx) error {
		subject, err := authenticatedSession(ctx, tx, p.Scope, p.SessionHash, p.BrowserHash, now)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE mayi.browser_sessions SET revoked=true WHERE tenant_id=$1 AND session_hash=$2 AND subject=$3 AND NOT revoked`, p.Scope.TenantID, id, subject)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id) VALUES($1,'user_session_revoked',$2)`, p.Scope.TenantID, subject)
		return err
	})
}

func (s *Store) TouchSession(ctx context.Context, p authentication.SessionProof, now time.Time) error {
	return s.authentication(ctx, p.Scope, func(tx pgx.Tx) error {
		if _, err := authenticatedSession(ctx, tx, p.Scope, p.SessionHash, p.BrowserHash, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE mayi.browser_sessions SET last_used_at=GREATEST(last_used_at,LEAST($3,clock_timestamp())) WHERE tenant_id=$1 AND session_hash=$2`, p.Scope.TenantID, p.SessionHash, now)
		return err
	})
}
