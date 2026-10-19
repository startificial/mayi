// Package postgres implements service-owned transaction and authorization ports.
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.UnitOfWork = (*Store)(nil)
var _ tokens.Authorizer = (*Store)(nil)
var _ tokens.ProofReplayStore = (*Store)(nil)

type Store struct{ pool *pgxpool.Pool }
type transaction struct {
	tx         pgx.Tx
	scope      grants.Scope
	version    uint64
	credential *tokens.Credential
}

func (s *Store) ConsumeProof(ctx context.Context, scope grants.Scope, p tokens.VerifiedProof) error {
	return s.Run(ctx, scope, func(value tokens.Transaction) error {
		tx := value.(*transaction)
		tag, err := tx.tx.Exec(ctx, `INSERT INTO mayi.proof_replays(tenant_id,thumbprint,proof_id,expires_at) SELECT $1,$2,$3,$4 WHERE $4>clock_timestamp() ON CONFLICT DO NOTHING`, scope.TenantID, p.Thumbprint, p.ID, p.ExpiresAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return tokens.ErrInvalidCredential
		}
		return nil
	})
}
func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, tokens.ErrUnavailable
	}
	return &Store{pool: pool}, nil
}

func scopeTransaction(ctx context.Context, tx pgx.Tx, scope grants.Scope) error {
	if !scope.Valid() {
		return tokens.ErrInvalidCredential
	}
	_, err := tx.Exec(ctx, "SELECT set_config('mayi.tenant_id',$1,true)", scope.TenantID)
	return err
}
func (s *Store) AuthorizeRedemption(ctx context.Context, caller tokens.Caller, _ string) (uint64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if err := scopeTransaction(ctx, tx, caller.Scope); err != nil {
		return 0, err
	}
	var version uint64
	err = tx.QueryRow(ctx, `SELECT t.policy_version FROM mayi.tenants t JOIN mayi.clients c USING(tenant_id)
 WHERE t.tenant_id=$1 AND t.issuer=$2 AND c.client_id=$3 AND c.enabled`, caller.Scope.TenantID, caller.Scope.Issuer, caller.ClientID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, tokens.ErrInvalidCredential
	}
	return version, err
}
func (s *Store) Run(ctx context.Context, scope grants.Scope, fn func(tokens.Transaction) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if err := scopeTransaction(ctx, tx, scope); err != nil {
		return err
	}
	var version uint64
	// Policy changes wait for this transaction. Grant/family/lineage changes all
	// take the same grant-row lock before mutation; never acquire family first.
	if err := tx.QueryRow(ctx, `SELECT policy_version FROM mayi.tenants WHERE tenant_id=$1 AND issuer=$2 FOR SHARE`, scope.TenantID, scope.Issuer).Scan(&version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return tokens.ErrInvalidCredential
		}
		return err
	}
	if err := fn(&transaction{tx: tx, scope: scope, version: version}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (t *transaction) Credential(ctx context.Context, hash string) (tokens.Credential, error) {
	c := tokens.Credential{Scope: t.scope}
	var objects []byte
	err := t.tx.QueryRow(ctx, `SELECT c.hash,c.kind,c.client_id,c.resource,c.grant_id,c.revision,
 c.pkce_challenge,c.binding_thumbprint,c.redirect_uri,c.ceiling_scopes,c.issued_at,c.expires_at,
 COALESCE(f.absolute_deadline,c.expires_at),c.consumed,c.origin_code,COALESCE(c.family_id,''),COALESCE(c.parent_issuance_id,''),c.object_ceiling
 FROM mayi.credentials c JOIN mayi.clients cl ON cl.tenant_id=c.tenant_id AND cl.client_id=c.client_id
 LEFT JOIN mayi.refresh_families f ON f.tenant_id=c.tenant_id AND f.family_id=c.family_id
 WHERE c.tenant_id=$1 AND c.hash=$2 AND cl.enabled FOR UPDATE OF c FOR SHARE OF cl`, t.scope.TenantID, hash).Scan(
		&c.Hash, &c.Kind, &c.ClientID, &c.Resource, &c.GrantID, &c.Revision, &c.PKCEChallenge, &c.BindingThumbprint, &c.RedirectURI, &c.CeilingScopes, &c.IssuedAt, &c.ExpiresAt, &c.FamilyDeadline, &c.Consumed, &c.OriginCode, &c.FamilyID, &c.ParentIssuanceID, &objects)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, tokens.ErrInvalidCredential
	}
	if err != nil {
		return c, err
	}
	c.ObjectCeiling, err = decodeObjectCeiling(objects, t.scope, c.Resource)
	if err != nil {
		return tokens.Credential{}, tokens.ErrInvalidCredential
	}
	t.credential = &c
	return c, nil
}
func (t *transaction) GrantRevision(ctx context.Context, id string, number uint64) (tokens.GrantState, error) {
	if t.credential == nil || t.credential.GrantID != id || t.credential.Revision != number {
		return tokens.GrantState{}, tokens.ErrInvalidCredential
	}
	spec := grants.RevisionSpec{Scope: t.scope, GrantID: id, Number: number}
	state := tokens.GrantState{PolicyVersion: t.version}
	var objects, currentObjects []byte
	err := t.tx.QueryRow(ctx, `SELECT g.client_id,g.subject,g.principal_type,g.resource,r.scopes,r.expires_at,g.current_scopes,g.expires_at,g.revoked,r.object_ceiling,g.current_object_ceiling
 FROM mayi.grants g JOIN mayi.grant_revisions r USING(tenant_id,grant_id)
 WHERE g.tenant_id=$1 AND g.grant_id=$2 AND r.revision=$3 FOR UPDATE OF g`, t.scope.TenantID, id, number).Scan(
		&spec.ClientID, &spec.Subject, &spec.PrincipalType, &spec.Resource, &spec.Scopes, &spec.ExpiresAt, &state.CurrentScopes, &state.AuthorizationDeadline, &state.Revoked, &objects, &currentObjects)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, tokens.ErrInvalidCredential
	}
	if err != nil {
		return state, err
	}
	spec.ObjectCeiling, err = decodeObjectCeiling(objects, t.scope, spec.Resource)
	if err != nil {
		return tokens.GrantState{}, tokens.ErrInvalidCredential
	}
	state.CurrentObjectCeiling, err = decodeObjectCeiling(currentObjects, t.scope, spec.Resource)
	if err != nil || spec.ObjectCeiling.IsZero() != state.CurrentObjectCeiling.IsZero() || spec.ObjectCeiling.IsZero() != t.credential.ObjectCeiling.IsZero() {
		return tokens.GrantState{}, tokens.ErrInvalidCredential
	}
	state.Revision, err = grants.NewRevision(spec)
	if err != nil {
		return state, err
	}
	var lineageRevoked bool
	if err := t.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.revoked_code_lineages WHERE tenant_id=$1 AND origin_code=$2)`, t.scope.TenantID, t.credential.OriginCode).Scan(&lineageRevoked); err != nil {
		return state, err
	}
	state.Revoked = state.Revoked || lineageRevoked
	if t.credential.Kind == tokens.RefreshToken {
		var revoked bool
		var deadline time.Time
		if err := t.tx.QueryRow(ctx, `SELECT revoked,absolute_deadline FROM mayi.refresh_families WHERE tenant_id=$1 AND family_id=$2 FOR UPDATE`, t.scope.TenantID, t.credential.FamilyID).Scan(&revoked, &deadline); err != nil {
			return state, err
		}
		state.Revoked = state.Revoked || revoked
		// The initial authentication projection may predate a concurrent policy
		// change. Apply the family deadline read under its final write lock.
		if deadline.Before(state.AuthorizationDeadline) {
			state.AuthorizationDeadline = deadline
		}
	}
	return state, nil
}
func (t *transaction) RevokeReplay(ctx context.Context, c tokens.Credential) error {
	if t.credential == nil || c.Hash != t.credential.Hash {
		return tokens.ErrInvalidCredential
	}
	// Same root lock as issuance: a replay cannot race a different family member
	// or a code-derived refresh past the final revocation check.
	var id string
	if err := t.tx.QueryRow(ctx, `SELECT grant_id FROM mayi.grants WHERE tenant_id=$1 AND grant_id=$2 FOR UPDATE`, t.scope.TenantID, c.GrantID).Scan(&id); err != nil {
		return err
	}
	if c.Kind == tokens.AuthorizationCode {
		if _, err := t.tx.Exec(ctx, `INSERT INTO mayi.revoked_code_lineages(tenant_id,origin_code) VALUES($1,$2) ON CONFLICT DO NOTHING`, t.scope.TenantID, c.OriginCode); err != nil {
			return err
		}
		if _, err := t.tx.Exec(ctx, `UPDATE mayi.issuances SET revoked=true WHERE tenant_id=$1 AND origin_code=$2`, t.scope.TenantID, c.OriginCode); err != nil {
			return err
		}
		if _, err := t.tx.Exec(ctx, `UPDATE mayi.refresh_families SET revoked=true WHERE tenant_id=$1 AND origin_code=$2`, t.scope.TenantID, c.OriginCode); err != nil {
			return err
		}
	} else {
		if _, err := t.tx.Exec(ctx, `UPDATE mayi.grants SET revoked=true WHERE tenant_id=$1 AND grant_id=$2`, t.scope.TenantID, c.GrantID); err != nil {
			return err
		}
		if _, err := t.tx.Exec(ctx, `UPDATE mayi.refresh_families SET revoked=true WHERE tenant_id=$1 AND grant_id=$2`, t.scope.TenantID, c.GrantID); err != nil {
			return err
		}
		if _, err := t.tx.Exec(ctx, `UPDATE mayi.issuances SET revoked=true WHERE tenant_id=$1 AND grant_id=$2`, t.scope.TenantID, c.GrantID); err != nil {
			return err
		}
	}
	_, err := t.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,grant_id,credential_hash) VALUES($1,'credential_replay',$2,$3)`, t.scope.TenantID, c.GrantID, c.Hash)
	return err
}
func (t *transaction) CommitIssuance(ctx context.Context, c tokens.Credential, i tokens.Issuance) error {
	if t.credential == nil || c.Hash != t.credential.Hash || i.Claims.Scope != t.scope || i.Claims.GrantID != c.GrantID || i.Claims.Revision != c.Revision {
		return tokens.ErrInvalidCredential
	}
	if !c.ObjectCeiling.IsZero() || !t.credential.ObjectCeiling.IsZero() {
		return tokens.ErrInvalidCredential
	}
	tag, err := t.tx.Exec(ctx, `UPDATE mayi.credentials SET consumed=true WHERE tenant_id=$1 AND hash=$2 AND NOT consumed AND expires_at>clock_timestamp() AND $3>clock_timestamp()`, t.scope.TenantID, c.Hash, i.Claims.ExpiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return tokens.ErrInvalidCredential
	}
	if _, err := t.tx.Exec(ctx, `INSERT INTO mayi.issuances(tenant_id,issuance_id,grant_id,revision,origin_code,family_id,parent_id,source_credential,resource,scopes,expires_at)
 VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11)`, t.scope.TenantID, i.Claims.ID, c.GrantID, c.Revision, c.OriginCode, c.FamilyID, c.ParentIssuanceID, c.Hash, i.Claims.Resource, i.Claims.Scopes, i.Claims.ExpiresAt); err != nil {
		return err
	}
	if c.Kind == tokens.RefreshToken {
		tag, err := t.tx.Exec(ctx, `INSERT INTO mayi.credentials(tenant_id,hash,kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,binding_thumbprint,origin_code,family_id,parent_issuance_id)
 SELECT $1,$2,'refresh_token',$3,$4,$5,$6,$7,clock_timestamp(),LEAST(clock_timestamp()+make_interval(secs=>f.idle_seconds),f.absolute_deadline),$8,$9,f.family_id,$10
 FROM mayi.refresh_families f WHERE f.tenant_id=$1 AND f.family_id=$11 AND NOT f.revoked AND f.absolute_deadline>clock_timestamp()`, t.scope.TenantID, i.RefreshHash, c.GrantID, c.Revision, c.Resource, c.ClientID, i.Claims.Scopes, c.BindingThumbprint, c.OriginCode, i.Claims.ID, c.FamilyID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return tokens.ErrInvalidCredential
		}
	}
	_, err = t.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,grant_id,credential_hash,issuance_id) VALUES($1,'token_issued',$2,$3,$4)`, t.scope.TenantID, c.GrantID, c.Hash, i.Claims.ID)
	return err
}
