package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/discovery"
)

var _ administration.Store = (*Store)(nil)
var _ discovery.Directory = (*Store)(nil)

type management struct {
	tx      pgx.Tx
	scope   grants.Scope
	version uint64
}

func classifyManagement(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return administration.ErrNotFound
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == "23505" || pe.Code == "23503") {
		return administration.ErrConflict
	}
	if errors.Is(err, administration.ErrConflict) || errors.Is(err, administration.ErrInvalid) || errors.Is(err, administration.ErrNotFound) {
		return err
	}
	return administration.ErrUnavailable
}
func (s *Store) RunManagement(ctx context.Context, scope grants.Scope, fn func(administration.Transaction) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return administration.ErrUnavailable
	}
	defer rollback(tx)
	if err := scopeTransaction(ctx, tx, scope); err != nil {
		return administration.ErrDenied
	}
	m := &management{tx: tx, scope: scope}
	if err := tx.QueryRow(ctx, `SELECT policy_version FROM mayi.tenants WHERE tenant_id=$1 AND issuer=$2 FOR UPDATE`, scope.TenantID, scope.Issuer).Scan(&m.version); err != nil {
		return classifyManagement(err)
	}
	if err := fn(m); err != nil {
		return classifyManagement(err)
	}
	return classifyManagement(tx.Commit(ctx))
}
func (m *management) Policy(ctx context.Context) (policy.Tenant, error) {
	p := policy.Tenant{Version: m.version}
	err := m.tx.QueryRow(ctx, `SELECT max_access_token_seconds,max_grant_seconds,require_binding,refresh_idle_seconds,refresh_absolute_seconds FROM mayi.tenant_policies WHERE tenant_id=$1`, m.scope.TenantID).Scan(&p.MaxAccessTokenSeconds, &p.MaxGrantSeconds, &p.RequireBinding, &p.RefreshIdleSeconds, &p.RefreshAbsoluteSeconds)
	return p, classifyManagement(err)
}
func (m *management) SetPolicy(ctx context.Context, p policy.Tenant) error {
	if p.Version != m.version+1 || !p.Valid() {
		return administration.ErrConflict
	}
	_, err := m.tx.Exec(ctx, `UPDATE mayi.tenant_policies SET max_access_token_seconds=$2,max_grant_seconds=$3,require_binding=$4,refresh_idle_seconds=$5,refresh_absolute_seconds=$6 WHERE tenant_id=$1`, m.scope.TenantID, p.MaxAccessTokenSeconds, p.MaxGrantSeconds, p.RequireBinding, p.RefreshIdle(), p.RefreshAbsolute())
	if err != nil {
		return err
	}
	_, err = m.tx.Exec(ctx, `UPDATE mayi.tenants SET policy_version=$2 WHERE tenant_id=$1`, m.scope.TenantID, p.Version)
	return err
}
func (m *management) CreateResource(ctx context.Context, r resources.Resource) error {
	_, err := m.tx.Exec(ctx, `INSERT INTO mayi.resources(tenant_id,resource_id,uri,name,access_token_seconds,require_binding,token_format) VALUES($1,$2,$3,$4,$5,$6,$7)`, m.scope.TenantID, r.ID, r.URI, r.Name, r.AccessTokenSeconds, r.RequireBinding, r.AccessTokenFormat())
	if err != nil {
		return err
	}
	for _, scope := range r.Scopes {
		if _, err := m.tx.Exec(ctx, `INSERT INTO mayi.resource_scopes(tenant_id,resource_id,name,description,requires_admin) VALUES($1,$2,$3,$4,$5)`, m.scope.TenantID, r.ID, scope.Name, scope.Description, scope.RequiresAdmin); err != nil {
			return err
		}
	}
	return nil
}
func (m *management) Resource(ctx context.Context, id string) (resources.Resource, error) {
	r := resources.Resource{ID: id}
	err := m.tx.QueryRow(ctx, `SELECT uri,name,access_token_seconds,require_binding,token_format FROM mayi.resources WHERE tenant_id=$1 AND resource_id=$2`, m.scope.TenantID, id).Scan(&r.URI, &r.Name, &r.AccessTokenSeconds, &r.RequireBinding, &r.TokenFormat)
	if err != nil {
		return r, classifyManagement(err)
	}
	rows, err := m.tx.Query(ctx, `SELECT name,description,requires_admin FROM mayi.resource_scopes WHERE tenant_id=$1 AND resource_id=$2 ORDER BY name`, m.scope.TenantID, id)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var scope resources.Scope
		if err := rows.Scan(&scope.Name, &scope.Description, &scope.RequiresAdmin); err != nil {
			return r, err
		}
		r.Scopes = append(r.Scopes, scope)
	}
	return r, rows.Err()
}
func (m *management) CreateClient(ctx context.Context, c clients.Client) error {
	if !c.Valid() {
		return administration.ErrInvalid
	}
	_, err := m.tx.Exec(ctx, `INSERT INTO mayi.clients(tenant_id,client_id,enabled,name,redirect_uris,access_token_seconds,auth_method,machine,introspection) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, m.scope.TenantID, c.ID, c.Enabled, c.Name, c.RedirectURIs, c.AccessTokenSeconds, clientAuthMethod(c.AuthMethod), c.Machine, c.Introspection)
	if err != nil {
		return err
	}
	for _, id := range c.Resources {
		if _, err := m.tx.Exec(ctx, `INSERT INTO mayi.client_resources VALUES($1,$2,$3)`, m.scope.TenantID, c.ID, id); err != nil {
			return err
		}
	}
	for _, typ := range c.AuthorizationDetailsTypes {
		tag, err := m.tx.Exec(ctx, `INSERT INTO mayi.client_object_types(tenant_id,client_id,resource_id,type_uri)
 SELECT p.tenant_id,$2,p.resource_id,p.type_uri FROM mayi.resource_object_profiles p
 JOIN mayi.client_resources c ON c.tenant_id=p.tenant_id AND c.resource_id=p.resource_id AND c.client_id=$2
 WHERE p.tenant_id=$1 AND p.type_uri=$3`, m.scope.TenantID, c.ID, typ)
		if err != nil {
			return classifyManagement(err)
		}
		if tag.RowsAffected() != 1 {
			return administration.ErrInvalid
		}
	}
	return nil
}
func (m *management) Client(ctx context.Context, id string) (clients.Client, error) {
	c := clients.Client{ID: id}
	err := m.tx.QueryRow(ctx, `SELECT name,redirect_uris,access_token_seconds,enabled,auth_method,machine,auth_version,introspection FROM mayi.clients WHERE tenant_id=$1 AND client_id=$2`, m.scope.TenantID, id).Scan(&c.Name, &c.RedirectURIs, &c.AccessTokenSeconds, &c.Enabled, &c.AuthMethod, &c.Machine, &c.AuthenticationVersion, &c.Introspection)
	if err != nil {
		return c, classifyManagement(err)
	}
	rows, err := m.tx.Query(ctx, `SELECT resource_id FROM mayi.client_resources WHERE tenant_id=$1 AND client_id=$2 ORDER BY resource_id`, m.scope.TenantID, id)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return c, err
		}
		c.Resources = append(c.Resources, id)
	}
	if err := rows.Err(); err != nil {
		return clients.Client{}, err
	}
	rows.Close()
	rows, err = m.tx.Query(ctx, `SELECT type_uri FROM mayi.client_object_types WHERE tenant_id=$1 AND client_id=$2 ORDER BY type_uri LIMIT $3`, m.scope.TenantID, id, clients.MaxAuthorizationDetailsTypes+1)
	if err != nil {
		return clients.Client{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var typ string
		if err := rows.Scan(&typ); err != nil {
			return clients.Client{}, err
		}
		c.AuthorizationDetailsTypes = append(c.AuthorizationDetailsTypes, typ)
	}
	if err := rows.Err(); err != nil {
		return clients.Client{}, err
	}
	if !c.Valid() {
		return clients.Client{}, administration.ErrUnavailable
	}
	return c, nil
}
func (m *management) Audit(ctx context.Context, event, actor, object string) error {
	_, err := m.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id,object_ref) VALUES($1,$2,$3,$4)`, m.scope.TenantID, event, actor, object)
	return err
}
func (m *management) PublishKey(ctx context.Context, key identity.PublicKey, now time.Time) error {
	if key.Version < 1 || key.ID == "" || key.X == "" || key.Y == "" || now.IsZero() {
		return administration.ErrInvalid
	}
	_, err := m.tx.Exec(ctx, `INSERT INTO mayi.signing_keys(tenant_id,version,key_id,x,y,published_at) VALUES($1,$2,$3,$4,$5,$6)`, m.scope.TenantID, key.Version, key.ID, key.X, key.Y, now)
	return err
}
func (m *management) ActivateKey(ctx context.Context, version int, now time.Time, lead time.Duration) error {
	var published time.Time
	if err := m.tx.QueryRow(ctx, `SELECT published_at FROM mayi.signing_keys WHERE tenant_id=$1 AND version=$2`, m.scope.TenantID, version).Scan(&published); err != nil {
		return classifyManagement(err)
	}
	if now.Before(published.Add(lead)) {
		return administration.ErrConflict
	}
	if _, err := m.tx.Exec(ctx, `UPDATE mayi.signing_keys SET active=false WHERE tenant_id=$1 AND active`, m.scope.TenantID); err != nil {
		return err
	}
	_, err := m.tx.Exec(ctx, `UPDATE mayi.signing_keys SET active=true WHERE tenant_id=$1 AND version=$2`, m.scope.TenantID, version)
	return err
}
func (s *Store) PublishedKeys(ctx context.Context, scope grants.Scope) ([]identity.PublicKey, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, discovery.ErrUnavailable
	}
	defer rollback(tx)
	if err := scopeTransaction(ctx, tx, scope); err != nil {
		return nil, discovery.ErrUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT k.key_id,k.version,k.x,k.y FROM mayi.signing_keys k JOIN mayi.tenants t USING(tenant_id) WHERE k.tenant_id=$1 AND t.issuer=$2 ORDER BY k.version`, scope.TenantID, scope.Issuer)
	if err != nil {
		return nil, discovery.ErrUnavailable
	}
	defer rows.Close()
	var keys []identity.PublicKey
	for rows.Next() {
		var key identity.PublicKey
		if err := rows.Scan(&key.ID, &key.Version, &key.X, &key.Y); err != nil {
			return nil, discovery.ErrUnavailable
		}
		keys = append(keys, key)
	}
	if rows.Err() != nil {
		return nil, discovery.ErrUnavailable
	}
	return keys, nil
}

// ProvisionTenant is an explicit, local operator operation using the owner role.
// It cannot be reached from the HTTP server or its restricted runtime role.
func (s *Store) ProvisionTenant(ctx context.Context, scope grants.Scope, key identity.PublicKey, p policy.Tenant, actor string) error {
	if !scope.Valid() || key.Version < 1 || key.ID == "" || key.X == "" || key.Y == "" || !p.Valid() || p.Version != 1 || actor == "" {
		return administration.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := scopeTransaction(ctx, tx, scope); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mayi.tenants VALUES($1,$2,1)`, scope.TenantID, scope.Issuer); err != nil {
		return classifyManagement(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mayi.tenant_policies VALUES($1,$2,$3,$4)`, scope.TenantID, p.MaxAccessTokenSeconds, p.MaxGrantSeconds, p.RequireBinding); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mayi.signing_keys VALUES($1,$2,$3,$4,$5,clock_timestamp(),true)`, scope.TenantID, key.Version, key.ID, key.X, key.Y); err != nil {
		return classifyManagement(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id,object_ref) VALUES($1,'tenant_provisioned',$2,$1)`, scope.TenantID, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func clientAuthMethod(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func (s *Store) AuthorizationDetailTypes(ctx context.Context, scope grants.Scope) ([]string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, discovery.ErrUnavailable
	}
	defer rollback(tx)
	if err := scopeTransaction(ctx, tx, scope); err != nil {
		return nil, discovery.ErrUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT p.type_uri FROM mayi.resource_object_profiles p JOIN mayi.tenants t USING(tenant_id) WHERE p.tenant_id=$1 AND t.issuer=$2 ORDER BY p.type_uri LIMIT 1025`, scope.TenantID, scope.Issuer)
	if err != nil {
		return nil, discovery.ErrUnavailable
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var typ string
		if err := rows.Scan(&typ); err != nil || !resources.ValidObjectTypeURI(typ) {
			return nil, discovery.ErrUnavailable
		}
		result = append(result, typ)
	}
	if rows.Err() != nil || len(result) > 1024 {
		return nil, discovery.ErrUnavailable
	}
	return result, nil
}
