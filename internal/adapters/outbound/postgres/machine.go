package postgres

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/tokens"
	"slices"
	"time"
)

var _ tokens.MachineStore = (*Store)(nil)

type machineTransaction struct {
	tx       *transaction
	caller   tokens.Caller
	resource string
	policy   *tokens.MachinePolicy
}

func (s *Store) RunMachine(ctx context.Context, caller tokens.Caller, resource string, fn func(tokens.MachineTransaction) error) error {
	return s.Run(ctx, caller.Scope, func(raw tokens.Transaction) error {
		t := raw.(*transaction)
		var client string
		if err := t.tx.QueryRow(ctx, `SELECT client_id FROM mayi.clients WHERE tenant_id=$1 AND client_id=$2 AND enabled AND machine AND auth_method<>'none' AND auth_version=$3 FOR SHARE`, caller.Scope.TenantID, caller.ClientID, caller.AuthenticationVersion).Scan(&client); err != nil {
			return tokens.ErrInvalidCredential
		}
		return fn(&machineTransaction{tx: t, caller: caller, resource: resource})
	})
}
func (m *machineTransaction) MachinePolicy(ctx context.Context) (tokens.MachinePolicy, error) {
	t := m.tx
	r, err := registration(ctx, t.tx, t.scope, t.version, m.caller.ClientID, m.resource)
	if err != nil {
		return tokens.MachinePolicy{}, tokens.ErrInvalidCredential
	}
	var objects []byte
	p := tokens.MachinePolicy{Profiles: r.ObjectProfiles, AccessSeconds: min(r.Client.AccessTokenSeconds, r.Resource.AccessTokenSeconds, r.Policy.MaxAccessTokenSeconds), GrantSeconds: r.Policy.MaxGrantSeconds, RequireBinding: r.Policy.RequireBinding || r.Resource.RequireBinding}
	if err := t.tx.QueryRow(ctx, `SELECT scopes,object_ceiling FROM mayi.machine_authorizations WHERE tenant_id=$1 AND client_id=$2 AND resource=$3 FOR SHARE`, t.scope.TenantID, m.caller.ClientID, m.resource).Scan(&p.Scopes, &objects); err != nil {
		return p, tokens.ErrInvalidCredential
	}
	p.Ceiling, err = decodeObjectCeiling(objects, t.scope, m.resource)
	if err != nil || p.Ceiling.IsZero() {
		return p, tokens.ErrInvalidCredential
	}
	var format string
	if err := t.tx.QueryRow(ctx, `SELECT token_format FROM mayi.resources WHERE tenant_id=$1 AND uri=$2`, t.scope.TenantID, m.resource).Scan(&format); err != nil {
		return p, err
	}
	p.Opaque = format == "opaque"
	if err := t.tx.QueryRow(ctx, `SELECT version FROM mayi.signing_keys WHERE tenant_id=$1 AND active`, t.scope.TenantID).Scan(&p.SigningVersion); err != nil {
		return p, err
	}
	// Catalog changes can only reduce machine policy, never confer vocabulary.
	catalog := map[string]bool{}
	for _, s := range r.Resource.Scopes {
		catalog[s.Name] = true
	}
	for _, s := range p.Scopes {
		if !catalog[s] {
			return p, tokens.ErrInvalidCredential
		}
	}
	m.policy = &p
	return p, nil
}
func (m *machineTransaction) CommitMachine(ctx context.Context, i tokens.Issuance) error {
	t := m.tx
	c := i.Claims
	if m.policy == nil || c.Scope != t.scope || c.Subject != m.caller.ClientID || c.ClientID != m.caller.ClientID || c.PrincipalType != "machine" || c.Resource != m.resource || c.Revision != 1 || !c.ObjectCeiling.IsSubsetOf(m.policy.Ceiling) || c.ObjectCeiling.IsZero() {
		return tokens.ErrInvalidCredential
	}
	if c.SigningKeyVersion != m.policy.SigningVersion || len(i.TokenHash) != 64 || c.ID == "" || c.GrantID == "" || len(c.Scopes) == 0 || !grants.ValidScopes(c.Scopes) || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.After(c.IssuedAt.Add(time.Duration(m.policy.AccessSeconds)*time.Second)) || m.policy.RequireBinding && c.BindingThumbprint == "" {
		return tokens.ErrInvalidCredential
	}
	for _, scope := range c.Scopes {
		if !slices.Contains(m.policy.Scopes, scope) {
			return tokens.ErrInvalidCredential
		}
	}
	if _, err := resources.ValidateObjectRequest(t.scope, m.resource, m.policy.Profiles, c.ObjectCeiling.Snapshot().Details); err != nil {
		return tokens.ErrInvalidCredential
	}
	objects, err := encodeObjectCeiling(c.ObjectCeiling, t.scope, m.resource)
	if err != nil {
		return err
	}
	if _, err := t.tx.Exec(ctx, `INSERT INTO mayi.grants(tenant_id,grant_id,client_id,subject,principal_type,resource,current_scopes,expires_at,current_object_ceiling) VALUES($1,$2,$3,$3,'machine',$4,$5,$6,$7)`, t.scope.TenantID, c.GrantID, c.ClientID, c.Resource, c.Scopes, c.ExpiresAt, objects); err != nil {
		return err
	}
	if _, err := t.tx.Exec(ctx, `INSERT INTO mayi.grant_revisions(tenant_id,grant_id,revision,scopes,expires_at,object_ceiling) VALUES($1,$2,1,$3,$4,$5)`, t.scope.TenantID, c.GrantID, c.Scopes, c.ExpiresAt, objects); err != nil {
		return err
	}
	tag, err := t.tx.Exec(ctx, `INSERT INTO mayi.issuances(tenant_id,issuance_id,grant_id,revision,resource,scopes,expires_at,object_ceiling,token_hash,issued_at,binding_thumbprint,signing_version) SELECT $1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11 WHERE $6>clock_timestamp()`, t.scope.TenantID, c.ID, c.GrantID, c.Resource, c.Scopes, c.ExpiresAt, objects, i.TokenHash, c.IssuedAt, c.BindingThumbprint, c.SigningKeyVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return tokens.ErrInvalidCredential
	}
	_, err = t.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,grant_id,actor_id,issuance_id) VALUES($1,'machine_token_issued',$2,$3,$4)`, t.scope.TenantID, c.GrantID, c.ClientID, c.ID)
	return err
}
