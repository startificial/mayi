package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.StatusStore = (*Store)(nil)

func statusCaller(ctx context.Context, t *transaction, c tokens.StatusCaller, introspection bool, resource string) error {
	var valid bool
	err := t.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.clients c WHERE c.tenant_id=$1 AND c.client_id=$2 AND c.enabled AND c.auth_version=$3 AND (NOT $4::boolean OR c.introspection AND EXISTS(SELECT 1 FROM mayi.client_resources a JOIN mayi.resources r USING(tenant_id,resource_id) WHERE a.tenant_id=c.tenant_id AND a.client_id=c.client_id AND r.uri=$5)))`, c.Scope.TenantID, c.ClientID, c.AuthenticationVersion, introspection, resource).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return tokens.ErrInvalidCredential
	}
	return nil
}
func (s *Store) AccessStatus(ctx context.Context, caller tokens.StatusCaller, hash, resource string) (tokens.Result, error) {
	var result tokens.Result
	err := s.Run(ctx, caller.Scope, func(raw tokens.Transaction) error {
		t := raw.(*transaction)
		if err := statusCaller(ctx, t, caller, true, resource); err != nil {
			return err
		}
		// This is an authentication/status projection: no payload or display data.
		c := domain.AccessClaims{Scope: caller.Scope, Resource: resource}
		var objects, currentObjects, revisionObjects []byte
		var currentScopes []string
		var active bool
		err := t.tx.QueryRow(ctx, `SELECT i.issuance_id,i.grant_id,i.revision,g.subject,g.principal_type,g.client_id,i.scopes,i.issued_at,i.expires_at,i.binding_thumbprint,i.signing_version,i.object_ceiling,g.current_object_ceiling,r.object_ceiling,g.current_scopes,
   NOT i.revoked AND NOT g.revoked AND cl.enabled AND i.client_metadata_digest=cl.metadata_digest
   AND (cl.metadata_digest='' OR EXISTS(SELECT 1 FROM mayi.client_metadata_policies mp WHERE mp.tenant_id=cl.tenant_id AND mp.version=cl.metadata_policy_version)) AND i.expires_at>clock_timestamp() AND i.issued_at<=clock_timestamp() AND g.expires_at>clock_timestamp() AND r.expires_at>clock_timestamp()
   AND NOT EXISTS(SELECT 1 FROM mayi.revoked_code_lineages l WHERE l.tenant_id=i.tenant_id AND l.origin_code=i.origin_code)
   AND (i.family_id IS NULL OR EXISTS(SELECT 1 FROM mayi.refresh_families f WHERE f.tenant_id=i.tenant_id AND f.family_id=i.family_id AND NOT f.revoked AND f.absolute_deadline>clock_timestamp()))
   AND (g.principal_type='machine' OR EXISTS(SELECT 1 FROM mayi.principal_memberships m WHERE m.tenant_id=g.tenant_id AND m.subject=g.subject AND m.active))
   FROM mayi.issuances i JOIN mayi.grants g USING(tenant_id,grant_id) JOIN mayi.grant_revisions r ON r.tenant_id=i.tenant_id AND r.grant_id=i.grant_id AND r.revision=i.revision JOIN mayi.clients cl ON cl.tenant_id=g.tenant_id AND cl.client_id=g.client_id
   WHERE i.tenant_id=$1 AND i.token_hash=$2 AND i.resource=$3`, caller.Scope.TenantID, hash, resource).Scan(&c.ID, &c.GrantID, &c.Revision, &c.Subject, &c.PrincipalType, &c.ClientID, &c.Scopes, &c.IssuedAt, &c.ExpiresAt, &c.BindingThumbprint, &c.SigningKeyVersion, &objects, &currentObjects, &revisionObjects, &currentScopes, &active)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !active {
			return nil
		}
		c.ObjectCeiling, err = decodeObjectCeiling(objects, caller.Scope, resource)
		if err != nil || c.ObjectCeiling.IsZero() {
			return nil
		}
		current, err := decodeObjectCeiling(currentObjects, caller.Scope, resource)
		if err != nil {
			return nil
		}
		original, err := decodeObjectCeiling(revisionObjects, caller.Scope, resource)
		if err != nil || !c.ObjectCeiling.IsSubsetOf(current) || !c.ObjectCeiling.IsSubsetOf(original) {
			return nil
		}
		registration, err := registration(ctx, t.tx, caller.Scope, t.version, c.ClientID, resource)
		if err != nil {
			return nil
		}
		if _, err := resources.ValidateObjectRequest(caller.Scope, resource, registration.ObjectProfiles, c.ObjectCeiling.Snapshot().Details); err != nil {
			return nil
		}
		if c.PrincipalType == "machine" {
			if !registration.Client.Machine {
				return nil
			}
			var policyScopes []string
			var policyObjects []byte
			if err := t.tx.QueryRow(ctx, `SELECT scopes,object_ceiling FROM mayi.machine_authorizations WHERE tenant_id=$1 AND client_id=$2 AND resource=$3`, caller.Scope.TenantID, c.ClientID, resource).Scan(&policyScopes, &policyObjects); err != nil {
				return nil
			}
			ceiling, err := decodeObjectCeiling(policyObjects, caller.Scope, resource)
			if err != nil || ceiling.IsZero() || !c.ObjectCeiling.IsSubsetOf(ceiling) {
				return nil
			}
			currentRevision, err := grants.NewRevision(grants.RevisionSpec{Scope: caller.Scope, GrantID: c.GrantID, Number: c.Revision, ClientID: c.ClientID, Subject: c.Subject, PrincipalType: "machine", Resource: resource, Scopes: policyScopes, ExpiresAt: c.ExpiresAt, ObjectCeiling: ceiling})
			if err != nil {
				return nil
			}
			if _, err = currentRevision.Narrow(policyScopes, c.Scopes); err != nil {
				return nil
			}
		} else if registration.Client.Machine {
			return nil
		}
		revision, err := grants.NewRevision(grants.RevisionSpec{Scope: caller.Scope, GrantID: c.GrantID, Number: c.Revision, ClientID: c.ClientID, Subject: c.Subject, PrincipalType: c.PrincipalType, Resource: resource, Scopes: currentScopes, ExpiresAt: c.ExpiresAt, ObjectCeiling: original})
		if err != nil {
			return nil
		}
		catalog := make([]string, 0, len(registration.Resource.Scopes))
		for _, p := range registration.Resource.Scopes {
			if c.PrincipalType == "machine" || !p.RequiresAdmin {
				catalog = append(catalog, p.Name)
			}
		}
		if _, err := revision.Narrow(catalog, c.Scopes, currentScopes); err != nil {
			return nil
		}
		if (registration.Policy.RequireBinding || registration.Resource.RequireBinding || registration.Client.RequireBinding) && c.BindingThumbprint == "" {
			return nil
		}
		if _, err := t.tx.Exec(ctx, `INSERT INTO mayi.grant_usage(tenant_id,grant_id,last_checked_at,token_checks) VALUES($1,$2,clock_timestamp(),1) ON CONFLICT(tenant_id,grant_id) DO UPDATE SET last_checked_at=excluded.last_checked_at,token_checks=mayi.grant_usage.token_checks+1`, caller.Scope.TenantID, c.GrantID); err != nil {
			return err
		}
		result = tokens.Result{Claims: c, ObjectProfiles: registration.ObjectProfiles}
		return nil
	})
	if err != nil {
		return tokens.Result{}, err
	}
	return result, nil
}
func (s *Store) RevokeCredential(ctx context.Context, caller tokens.StatusCaller, hash, kind string) error {
	return s.Run(ctx, caller.Scope, func(raw tokens.Transaction) error {
		t := raw.(*transaction)
		if err := statusCaller(ctx, t, caller, false, ""); err != nil {
			return err
		}
		var grantID, issuance string
		if kind == tokens.RefreshToken {
			err := t.tx.QueryRow(ctx, `SELECT grant_id FROM mayi.credentials WHERE tenant_id=$1 AND hash=$2 AND kind='refresh_token' AND client_id=$3`, caller.Scope.TenantID, hash, caller.ClientID).Scan(&grantID)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
		} else {
			err := t.tx.QueryRow(ctx, `SELECT i.grant_id,i.issuance_id FROM mayi.issuances i JOIN mayi.grants g USING(tenant_id,grant_id) WHERE i.tenant_id=$1 AND i.token_hash=$2 AND g.client_id=$3`, caller.Scope.TenantID, hash, caller.ClientID).Scan(&grantID, &issuance)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
		}
		if _, err := t.tx.Exec(ctx, `SELECT grant_id FROM mayi.grants WHERE tenant_id=$1 AND grant_id=$2 FOR UPDATE`, caller.Scope.TenantID, grantID); err != nil {
			return err
		}
		if issuance != "" {
			if _, err := t.tx.Exec(ctx, `UPDATE mayi.issuances SET revoked=true WHERE tenant_id=$1 AND issuance_id=$2`, caller.Scope.TenantID, issuance); err != nil {
				return err
			}
		} else {
			if err := revokeGrant(ctx, t.tx, caller.Scope, grantID); err != nil {
				return err
			}
		}
		_, err := t.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,grant_id,actor_id) VALUES($1,'credential_revoked',$2,$3)`, caller.Scope.TenantID, grantID, caller.ClientID)
		return err
	})
}
func revokeGrant(ctx context.Context, tx pgx.Tx, scope grants.Scope, id string) error {
	for _, table := range []string{"grants", "refresh_families", "issuances"} {
		if _, err := tx.Exec(ctx, `UPDATE mayi.`+table+` SET revoked=true WHERE tenant_id=$1 AND grant_id=$2`, scope.TenantID, id); err != nil {
			return err
		}
	}
	return nil
}
