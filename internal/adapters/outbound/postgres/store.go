// Package postgres implements service-owned transaction and authorization ports.
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/delivery"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.UnitOfWork = (*Store)(nil)
var _ tokens.Authorizer = (*Store)(nil)
var _ tokens.ProofReplayStore = (*Store)(nil)

type Store struct{ pool *pgxpool.Pool }
type transaction struct {
	tx                pgx.Tx
	scope             grants.Scope
	version           uint64
	credential        *tokens.Credential
	credentialObjects grants.ObjectCeiling
	grant             *tokens.GrantState
}

func (s *Store) ConsumeProof(ctx context.Context, scope grants.Scope, p tokens.ProofReplay) error {
	return s.Run(ctx, scope, func(value tokens.Transaction) error {
		tx := value.(*transaction)
		if _, err := tx.tx.Exec(ctx, `DELETE FROM mayi.proof_replays WHERE tenant_id=$1 AND (thumbprint,proof_id) IN (SELECT thumbprint,proof_id FROM mayi.proof_replays WHERE tenant_id=$1 AND expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 100)`, scope.TenantID); err != nil {
			return err
		}
		tag, err := tx.tx.Exec(ctx, `INSERT INTO mayi.proof_replays(tenant_id,thumbprint,proof_id,expires_at) SELECT $1,$2,$3,$4 WHERE $4>clock_timestamp() AND EXISTS(SELECT 1 FROM mayi.proof_nonces WHERE tenant_id=$1 AND purpose=$5 AND target=$6 AND thumbprint=$2 AND nonce_hash=$7 AND expires_at>clock_timestamp()) ON CONFLICT DO NOTHING`, scope.TenantID, p.Thumbprint, p.ID, p.ExpiresAt, p.Purpose, p.Target, p.NonceHash)
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
	metadata := delivery.Metadata(ctx)
	_, err := tx.Exec(ctx, "SELECT set_config('mayi.tenant_id',$1,true),set_config('mayi.request_id',$2,true),set_config('mayi.remote_ip',$3,true),set_config('mayi.user_agent',$4,true)", scope.TenantID, metadata.RequestID, metadata.IP, metadata.UserAgent)
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
 WHERE t.tenant_id=$1 AND t.issuer=$2 AND c.client_id=$3 AND c.enabled AND ($4::bigint=0 OR c.auth_version=$4)`, caller.Scope.TenantID, caller.Scope.Issuer, caller.ClientID, caller.AuthenticationVersion).Scan(&version)
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
	err := t.tx.QueryRow(ctx, `SELECT c.hash,c.kind,c.client_id,c.resource,c.grant_id,c.revision,
 c.pkce_challenge,c.binding_thumbprint,c.redirect_uri,c.ceiling_scopes,c.issued_at,c.expires_at,
 COALESCE(f.absolute_deadline,c.expires_at),c.consumed,c.origin_code,COALESCE(c.family_id,''),COALESCE(c.parent_issuance_id,''),c.object_ceiling IS NOT NULL,cl.auth_version
 FROM mayi.credentials c JOIN mayi.clients cl ON cl.tenant_id=c.tenant_id AND cl.client_id=c.client_id
 LEFT JOIN mayi.refresh_families f ON f.tenant_id=c.tenant_id AND f.family_id=c.family_id
 WHERE c.tenant_id=$1 AND c.hash=$2 AND cl.enabled FOR UPDATE OF c FOR SHARE OF cl`, t.scope.TenantID, hash).Scan(
		&c.Hash, &c.Kind, &c.ClientID, &c.Resource, &c.GrantID, &c.Revision, &c.PKCEChallenge, &c.BindingThumbprint, &c.RedirectURI, &c.CeilingScopes, &c.IssuedAt, &c.ExpiresAt, &c.FamilyDeadline, &c.Consumed, &c.OriginCode, &c.FamilyID, &c.ParentIssuanceID, &c.ObjectBound, &c.ClientAuthenticationVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, tokens.ErrInvalidCredential
	}
	if err != nil {
		return c, err
	}
	t.credential = &c
	return c, nil
}
func (t *transaction) CredentialObjects(ctx context.Context, c tokens.Credential) (grants.ObjectCeiling, error) {
	t.credentialObjects = grants.ObjectCeiling{}
	if t.credential == nil || t.credential.Hash != c.Hash || !c.ObjectBound || c.Scope != t.scope {
		return grants.ObjectCeiling{}, tokens.ErrInvalidCredential
	}
	var data []byte
	if err := t.tx.QueryRow(ctx, `SELECT c.object_ceiling FROM mayi.credentials c
 WHERE c.tenant_id=$1 AND c.hash=$2 AND EXISTS(
 SELECT 1 FROM mayi.credentials origin JOIN mayi.authorization_transactions w ON w.tenant_id=origin.tenant_id AND w.handle_hash=origin.authorization_hash
 JOIN mayi.authorization_object_presentations p ON p.tenant_id=w.tenant_id AND p.handle_hash=w.handle_hash
 WHERE origin.tenant_id=c.tenant_id AND origin.hash=c.origin_code AND origin.kind='authorization_code' AND w.code_hash=origin.hash AND w.status='approved' AND w.pushed_request_hash IS NOT NULL AND p.object_ceiling=w.object_ceiling)`, t.scope.TenantID, c.Hash).Scan(&data); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return grants.ObjectCeiling{}, tokens.ErrInvalidCredential
		}
		return grants.ObjectCeiling{}, err
	}
	ceiling, err := decodeObjectCeiling(data, t.scope, c.Resource)
	if err != nil || ceiling.IsZero() {
		return grants.ObjectCeiling{}, tokens.ErrInvalidCredential
	}
	t.credentialObjects = ceiling
	return ceiling, nil
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
	if err != nil || spec.ObjectCeiling.IsZero() != state.CurrentObjectCeiling.IsZero() || (!spec.ObjectCeiling.IsZero()) != t.credential.ObjectBound {
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
	current, err := registration(ctx, t.tx, t.scope, t.version, spec.ClientID, spec.Resource)
	if err != nil {
		return tokens.GrantState{}, tokens.ErrInvalidCredential
	}
	if !current.Resource.Valid() || !current.Policy.Valid() || (current.Policy.RequireBinding || current.Resource.RequireBinding || current.Client.RequireBinding) && t.credential.BindingThumbprint == "" {
		return tokens.GrantState{}, tokens.ErrInvalidCredential
	}
	catalog := make([]string, 0, len(current.Resource.Scopes))
	for _, permission := range current.Resource.Scopes {
		if !permission.RequiresAdmin {
			catalog = append(catalog, permission.Name)
		}
	}
	state.CurrentScopes, err = state.Revision.Narrow(catalog, nil, state.CurrentScopes)
	if err != nil {
		return tokens.GrantState{}, tokens.ErrInvalidCredential
	}
	state.ObjectProfiles = current.ObjectProfiles
	state.MaxAccessTokenSeconds = min(current.Policy.MaxAccessTokenSeconds, current.Client.AccessTokenSeconds, current.Resource.AccessTokenSeconds)
	var format string
	if err := t.tx.QueryRow(ctx, `SELECT token_format FROM mayi.resources WHERE tenant_id=$1 AND uri=$2`, t.scope.TenantID, spec.Resource).Scan(&format); err != nil {
		return tokens.GrantState{}, err
	}
	state.Opaque = format == "opaque"
	if err := t.tx.QueryRow(ctx, `SELECT refresh_idle_seconds,refresh_absolute_seconds FROM mayi.tenant_policies WHERE tenant_id=$1`, t.scope.TenantID).Scan(&state.RefreshIdleSeconds, &state.RefreshAbsoluteSeconds); err != nil {
		return tokens.GrantState{}, err
	}
	if t.credential.Kind == tokens.RefreshToken {
		var policyDeadline time.Time
		if err := t.tx.QueryRow(ctx, `SELECT created_at+make_interval(secs=>$3) FROM mayi.refresh_families WHERE tenant_id=$1 AND family_id=$2`, t.scope.TenantID, t.credential.FamilyID, state.RefreshAbsoluteSeconds).Scan(&policyDeadline); err != nil {
			return tokens.GrantState{}, err
		}
		if policyDeadline.Before(state.AuthorizationDeadline) {
			state.AuthorizationDeadline = policyDeadline
		}
	}
	err = t.tx.QueryRow(ctx, `SELECT version FROM mayi.signing_keys WHERE tenant_id=$1 AND active`, t.scope.TenantID).Scan(&state.SigningKeyVersion)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return tokens.GrantState{}, err
	}
	var authTime *time.Time
	err = t.tx.QueryRow(ctx, `SELECT o.oidc,o.nonce,o.offline_access,e.authenticated_at FROM mayi.credentials c JOIN mayi.authorization_transactions w ON w.tenant_id=c.tenant_id AND w.handle_hash=c.authorization_hash JOIN mayi.authorization_options o ON o.tenant_id=w.tenant_id AND o.handle_hash=w.handle_hash LEFT JOIN mayi.session_authentication e ON e.tenant_id=w.tenant_id AND e.session_hash=w.consent_session_hash WHERE c.tenant_id=$1 AND c.hash=$2 AND w.status='approved'`, t.scope.TenantID, t.credential.OriginCode).Scan(&state.OIDC, &state.Nonce, &state.OfflineAccess, &authTime)
	if err != nil {
		return tokens.GrantState{}, tokens.ErrInvalidCredential
	}
	if authTime != nil {
		state.AuthenticatedAt = *authTime
	}
	if t.credential.ObjectBound && spec.PrincipalType == "user" {
		var member bool
		if err := t.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.principal_memberships WHERE tenant_id=$1 AND subject=$2 AND active)`, t.scope.TenantID, spec.Subject).Scan(&member); err != nil {
			return tokens.GrantState{}, err
		}
		state.Revoked = state.Revoked || !member
	}
	t.grant = &state
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
	if t.grant == nil || t.grant.Revoked || t.grant.PolicyVersion != t.version {
		return tokens.ErrInvalidCredential
	}
	stored := t.credential
	spec := t.grant.Revision.Snapshot()
	if c.Kind != stored.Kind || c.ClientID != stored.ClientID || c.Resource != stored.Resource || c.GrantID != stored.GrantID || c.Revision != stored.Revision || c.BindingThumbprint != stored.BindingThumbprint || c.OriginCode != stored.OriginCode || c.FamilyID != stored.FamilyID || c.ParentIssuanceID != stored.ParentIssuanceID || stored.Consumed || i.Claims.ClientID != spec.ClientID || i.Claims.Subject != spec.Subject || i.Claims.PrincipalType != spec.PrincipalType || i.Claims.Resource != spec.Resource || i.Claims.BindingThumbprint != stored.BindingThumbprint || i.Claims.ID == "" || i.Claims.IssuedAt.IsZero() || !i.Claims.ExpiresAt.After(i.Claims.IssuedAt) || i.Claims.ExpiresAt.After(spec.ExpiresAt) || i.Claims.ExpiresAt.After(t.grant.AuthorizationDeadline) || t.grant.MaxAccessTokenSeconds <= 0 || i.Claims.ExpiresAt.After(i.Claims.IssuedAt.Add(time.Duration(t.grant.MaxAccessTokenSeconds)*time.Second)) {
		return tokens.ErrInvalidCredential
	}
	if scopes, err := t.grant.Revision.Narrow(t.grant.CurrentScopes, i.Claims.Scopes, stored.CeilingScopes); err != nil || len(scopes) == 0 || len(i.Claims.Scopes) == 0 {
		return tokens.ErrInvalidCredential
	}
	if c.ObjectBound != !i.Claims.ObjectCeiling.IsZero() || c.ObjectBound != t.credential.ObjectBound {
		return tokens.ErrInvalidCredential
	}
	var objects []byte
	if c.ObjectBound {
		if t.grant == nil || t.credentialObjects.IsZero() || !i.Claims.ObjectCeiling.IsSubsetOf(t.credentialObjects) || !i.Claims.ObjectCeiling.IsSubsetOf(t.grant.Revision.Snapshot().ObjectCeiling) || !i.Claims.ObjectCeiling.IsSubsetOf(t.grant.CurrentObjectCeiling) {
			return tokens.ErrInvalidCredential
		}
		var err error
		objects, err = encodeObjectCeiling(i.Claims.ObjectCeiling, t.scope, c.Resource)
		if err != nil {
			return tokens.ErrInvalidCredential
		}
	}
	tag, err := t.tx.Exec(ctx, `UPDATE mayi.credentials SET consumed=true WHERE tenant_id=$1 AND hash=$2 AND NOT consumed AND expires_at>clock_timestamp() AND $3>clock_timestamp()`, t.scope.TenantID, c.Hash, i.Claims.ExpiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return tokens.ErrInvalidCredential
	}
	familyID := c.FamilyID
	if i.NewFamily.ID != "" {
		if c.Kind != tokens.AuthorizationCode || !t.grant.OfflineAccess || i.RefreshHash == "" || i.NewFamily.IdleSeconds < 60 || i.NewFamily.IdleSeconds > t.grant.RefreshIdleSeconds || i.NewFamily.Deadline.After(i.Claims.IssuedAt.Add(time.Duration(t.grant.RefreshAbsoluteSeconds)*time.Second)) || i.NewFamily.Deadline.After(t.grant.AuthorizationDeadline) {
			return tokens.ErrInvalidCredential
		}
		familyID = i.NewFamily.ID
		if _, err := t.tx.Exec(ctx, `INSERT INTO mayi.refresh_families(tenant_id,family_id,grant_id,revision,origin_code,absolute_deadline,idle_seconds,object_ceiling) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.scope.TenantID, familyID, c.GrantID, c.Revision, c.OriginCode, i.NewFamily.Deadline, i.NewFamily.IdleSeconds, objects); err != nil {
			return err
		}
	}
	if _, err := t.tx.Exec(ctx, `INSERT INTO mayi.issuances(tenant_id,issuance_id,grant_id,revision,origin_code,family_id,parent_id,source_credential,resource,scopes,expires_at,object_ceiling,token_hash,issued_at,binding_thumbprint,signing_version)
 VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11,$12,NULLIF($13,''),$14,$15,$16)`, t.scope.TenantID, i.Claims.ID, c.GrantID, c.Revision, c.OriginCode, familyID, c.ParentIssuanceID, c.Hash, i.Claims.Resource, i.Claims.Scopes, i.Claims.ExpiresAt, objects, i.TokenHash, i.Claims.IssuedAt, i.Claims.BindingThumbprint, i.Claims.SigningKeyVersion); err != nil {
		return err
	}
	if i.RefreshHash != "" {
		tag, err := t.tx.Exec(ctx, `INSERT INTO mayi.credentials(tenant_id,hash,kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,binding_thumbprint,origin_code,family_id,parent_issuance_id,object_ceiling)
 SELECT $1,$2,'refresh_token',$3,$4,$5,$6,$7,clock_timestamp(),LEAST(clock_timestamp()+make_interval(secs=>LEAST(f.idle_seconds,$13)),f.absolute_deadline,$14),$8,$9,f.family_id,$10,$12
 FROM mayi.refresh_families f WHERE f.tenant_id=$1 AND f.family_id=$11 AND NOT f.revoked AND f.absolute_deadline>clock_timestamp()`, t.scope.TenantID, i.RefreshHash, c.GrantID, c.Revision, c.Resource, c.ClientID, i.Claims.Scopes, c.BindingThumbprint, c.OriginCode, i.Claims.ID, familyID, objects, t.grant.RefreshIdleSeconds, t.grant.AuthorizationDeadline)
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
