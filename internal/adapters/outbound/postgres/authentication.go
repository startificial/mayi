package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	"github.com/startificial/mayi/internal/services/authentication"
	"time"
)

var _ authentication.Store = (*Store)(nil)

func (s *Store) authentication(ctx context.Context, scope grants.Scope, fn func(pgx.Tx) error) error {
	if !scope.Valid() {
		return authentication.ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return authentication.ErrUnavailable
	}
	defer rollback(tx)
	if err = scopeTransaction(ctx, tx, scope); err != nil {
		return authentication.ErrDenied
	}
	var tenant string
	if err = tx.QueryRow(ctx, `SELECT tenant_id FROM mayi.tenants WHERE tenant_id=$1 AND issuer=$2 FOR UPDATE`, scope.TenantID, scope.Issuer).Scan(&tenant); err != nil {
		return authentication.ErrDenied
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return authentication.ErrUnavailable
	}
	return nil
}
func loginReference(ctx context.Context, tx pgx.Tx, l identity.Login, now time.Time) error {
	var handle string
	err := tx.QueryRow(ctx, `SELECT w.handle_hash FROM mayi.authorization_transactions w
 JOIN mayi.tenants t USING(tenant_id) JOIN mayi.clients c USING(tenant_id,client_id)
 WHERE w.tenant_id=$1 AND w.handle_hash=$2 AND w.browser_binding_hash=$3 AND w.status='pending'
 AND w.consent_session_hash IS NULL AND w.policy_version=t.policy_version AND c.enabled
 AND w.created_at<=$4 AND w.expires_at>$4 AND w.expires_at>= $5 AND w.expires_at>clock_timestamp() FOR UPDATE OF w`, l.TenantIssuer.TenantID, l.AuthorizationHash, l.BrowserHash, now, l.ExpiresAt).Scan(&handle)
	if err != nil {
		return authentication.ErrDenied
	}
	return nil
}
func (s *Store) StartLogin(ctx context.Context, l identity.Login) error {
	if !l.Valid() {
		return authentication.ErrDenied
	}
	return s.authentication(ctx, l.TenantIssuer, func(tx pgx.Tx) error {
		if err := loginReference(ctx, tx, l, l.CreatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO mayi.login_attempts(tenant_id,state_hash,provider_id,authorization_hash,browser_hash,nonce_hash,verifier_hash,created_at,expires_at,provider_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, l.TenantIssuer.TenantID, l.StateHash, l.ProviderID, l.AuthorizationHash, l.BrowserHash, l.NonceHash, l.VerifierHash, l.CreatedAt, l.ExpiresAt, l.ProviderHash)
		return err
	})
}
func (s *Store) ClaimLogin(ctx context.Context, l identity.Login, now time.Time) error {
	if !l.ActiveAt(now) {
		return authentication.ErrDenied
	}
	return s.authentication(ctx, l.TenantIssuer, func(tx pgx.Tx) error {
		if err := loginReference(ctx, tx, l, now); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE mayi.login_attempts SET claimed_at=$10 WHERE tenant_id=$1 AND state_hash=$2 AND provider_id=$3 AND authorization_hash=$4 AND browser_hash=$5 AND nonce_hash=$6 AND verifier_hash=$7 AND created_at=$8 AND expires_at=$9 AND provider_hash=$11 AND claimed_at IS NULL AND expires_at>clock_timestamp()`, l.TenantIssuer.TenantID, l.StateHash, l.ProviderID, l.AuthorizationHash, l.BrowserHash, l.NonceHash, l.VerifierHash, l.CreatedAt, l.ExpiresAt, now, l.ProviderHash)
		if err != nil {
			return authentication.ErrUnavailable
		}
		if tag.RowsAffected() != 1 {
			return authentication.ErrDenied
		}
		return nil
	})
}
func (s *Store) CompleteLogin(ctx context.Context, l identity.Login, evidence identity.Assertion, sessionHash, previousHash string, now time.Time) error {
	if !evidence.ValidFor(l, now) {
		return authentication.ErrDenied
	}
	return s.authentication(ctx, l.TenantIssuer, func(tx pgx.Tx) error {
		if err := loginReference(ctx, tx, l, now); err != nil {
			return err
		}
		// Authentication/ownership projection only: an upstream assertion never
		// establishes membership or authority by its email or signature alone.
		var subject string
		err := tx.QueryRow(ctx, `SELECT i.subject FROM mayi.external_identities i JOIN mayi.principal_memberships m USING(tenant_id,subject) WHERE i.tenant_id=$1 AND i.provider_id=$2 AND i.upstream_issuer=$3 AND i.upstream_subject=$4 AND m.active`, l.TenantIssuer.TenantID, l.ProviderID, evidence.Issuer, evidence.Subject).Scan(&subject)
		if err != nil {
			return authentication.ErrDenied
		}
		tag, err := tx.Exec(ctx, `UPDATE mayi.login_attempts SET completed_at=$10 WHERE tenant_id=$1 AND state_hash=$2 AND provider_id=$3 AND authorization_hash=$4 AND browser_hash=$5 AND nonce_hash=$6 AND verifier_hash=$7 AND created_at=$8 AND expires_at=$9 AND provider_hash=$11 AND claimed_at IS NOT NULL AND claimed_at<=$10 AND completed_at IS NULL AND expires_at>clock_timestamp()`, l.TenantIssuer.TenantID, l.StateHash, l.ProviderID, l.AuthorizationHash, l.BrowserHash, l.NonceHash, l.VerifierHash, l.CreatedAt, l.ExpiresAt, now, l.ProviderHash)
		if err != nil {
			return authentication.ErrUnavailable
		}
		if tag.RowsAffected() != 1 {
			return authentication.ErrDenied
		}
		if previousHash != "" {
			if _, err = tx.Exec(ctx, `UPDATE mayi.browser_sessions s SET revoked=true FROM mayi.session_authentication e WHERE s.tenant_id=$1 AND s.session_hash=$2 AND e.tenant_id=s.tenant_id AND e.session_hash=s.session_hash AND e.browser_hash=$3`, l.TenantIssuer.TenantID, previousHash, l.BrowserHash); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO mayi.browser_sessions(tenant_id,session_hash,subject,expires_at) VALUES($1,$2,$3,$4)`, l.TenantIssuer.TenantID, sessionHash, subject, now.Add(identity.SessionLifetime)); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO mayi.session_authentication VALUES($1,$2,$3,$4,$5,$6)`, l.TenantIssuer.TenantID, sessionHash, l.BrowserHash, l.ProviderID, evidence.Issuer, evidence.AuthenticatedAt); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id,object_ref) VALUES($1,'session_authenticated',$2,$3)`, l.TenantIssuer.TenantID, subject, l.AuthorizationHash)
		return err
	})
}
func (s *Store) EndSession(ctx context.Context, scope grants.Scope, hash, browserHash string, now time.Time) error {
	return s.authentication(ctx, scope, func(tx pgx.Tx) error {
		var subject string
		// Ending one's browser-bound session reduces authority. Membership loss
		// must not prevent that revocation or allow reactivation to revive it.
		err := tx.QueryRow(ctx, `UPDATE mayi.browser_sessions s SET revoked=true FROM mayi.session_authentication e WHERE s.tenant_id=$1 AND s.session_hash=$2 AND e.tenant_id=s.tenant_id AND e.session_hash=s.session_hash AND e.browser_hash=$3 AND NOT s.revoked AND s.expires_at>$4 AND s.expires_at>clock_timestamp() RETURNING s.subject`, scope.TenantID, hash, browserHash, now).Scan(&subject)
		if err != nil {
			return authentication.ErrDenied
		}
		_, err = tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id,object_ref) VALUES($1,'session_ended',$2,'browser_session')`, scope.TenantID, subject)
		return err
	})
}
