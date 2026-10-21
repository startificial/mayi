package postgres

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/authorization"
)

var _ authorization.ObjectConsentAuthority = (*ResourceConsent)(nil)

// ResourceConsentConfig pins a trusted resource in the same database as Mayi.
// Its owner maintains mayi_resource; Mayi never writes the owner ACL.
type ResourceConsentConfig struct {
	Scope    grants.Scope
	Resource string
}

type ResourceConsent struct {
	store  *Store
	owners []ResourceConsentConfig
}

// resourceGuard is private to this adapter family. Its context is a transaction
// enlistment capability, not a service locator or a handler-visible database.
type resourceGuardKey struct{}
type resourceGuard struct {
	store           *Store
	scope           grants.Scope
	tx              pgx.Tx
	used, committed bool
}

func NewResourceConsent(store *Store, owners []ResourceConsentConfig) (*ResourceConsent, error) {
	if store == nil || len(owners) == 0 || len(owners) > 32 {
		return nil, authorization.ErrUnavailable
	}
	for i, owner := range owners {
		if !owner.Scope.Valid() || !resources.ValidURI(owner.Resource) {
			return nil, authorization.ErrUnavailable
		}
		for _, other := range owners[:i] {
			if owner.Scope == other.Scope && owner.Resource == other.Resource {
				return nil, authorization.ErrUnavailable
			}
		}
	}
	return &ResourceConsent{store: store, owners: slices.Clone(owners)}, nil
}

// Check rejects owner-level or ACL-writing runtime access. The resource owner
// installs and maintains the contract; Mayi cannot create or repair it at startup.
func (a *ResourceConsent) Check(ctx context.Context) error {
	var safe bool
	err := a.store.pool.QueryRow(ctx, `SELECT
 NOT has_schema_privilege(current_user,'mayi_resource','CREATE') AND
 (SELECT count(*)=3 AND bool_and(c.relrowsecurity AND c.relforcerowsecurity
   AND NOT pg_has_role(current_user,c.relowner,'MEMBER')
   AND has_table_privilege(current_user,c.oid,'SELECT')
   AND NOT has_table_privilege(current_user,c.oid,'INSERT,DELETE,TRUNCATE,TRIGGER'))
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='mayi_resource' AND c.relkind='r' AND c.relname IN ('authorities','permissions','labels'))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute p JOIN pg_class c ON c.oid=p.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='mayi_resource' AND c.relname IN ('authorities','permissions','labels') AND p.attnum>0 AND NOT p.attisdropped AND p.attname<>'lock_marker'
  AND has_column_privilege(current_user,c.oid,p.attnum,'UPDATE'))
 AND has_column_privilege(current_user,'mayi_resource.authorities','lock_marker','UPDATE')
 AND has_column_privilege(current_user,'mayi_resource.labels','lock_marker','UPDATE')
 AND (SELECT count(*)=2 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='mayi_resource' AND t.tgenabled='O' AND NOT t.tgisinternal
  AND (c.relname='authorities' AND t.tgname='authority_changed' OR c.relname='permissions' AND t.tgname='permission_changed'))`).Scan(&safe)
	if err != nil || !safe {
		return authorization.ErrUnavailable
	}
	return nil
}

func (a *ResourceConsent) WithObjectConsent(ctx context.Context, q authorization.ObjectConsentQuery, fn func(context.Context, domain.ObjectConsentProjection) error) error {
	if fn == nil || !q.Ceiling.BoundTo(q.TenantIssuer, q.Ceiling.Snapshot().Resource) || len(q.Ceiling.Snapshot().Details) == 0 || !grants.ValidUserSubject(q.Subject) || !clients.ValidClientID(q.ClientID) || !domain.ValidHandleHash(q.AuthorizationHash) {
		return authorization.ErrDenied
	}
	for _, owner := range a.owners {
		if owner.Scope == q.TenantIssuer && owner.Resource == q.Ceiling.Snapshot().Resource {
			return a.withOwner(ctx, owner, q, fn)
		}
	}
	return authorization.ErrDenied
}

func (a *ResourceConsent) withOwner(ctx context.Context, owner ResourceConsentConfig, q authorization.ObjectConsentQuery, fn func(context.Context, domain.ObjectConsentProjection) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := a.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return authorization.ErrUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err := tx.Exec(ctx, `SELECT set_config('mayi_resource.tenant_id',$1,true),set_config('mayi_resource.issuer',$2,true),set_config('mayi_resource.resource',$3,true),set_config('statement_timeout','4000',true),set_config('lock_timeout','2000',true)`, owner.Scope.TenantID, owner.Scope.Issuer, owner.Resource); err != nil {
		return authorization.ErrUnavailable
	}
	var version uint64
	// Writers take this same root FOR UPDATE before changing any permission.
	// A missing authority is a denial, never an invitation to provision one.
	err = tx.QueryRow(ctx, `SELECT version FROM mayi_resource.authorities WHERE tenant_id=$1 AND issuer=$2 AND resource=$3 AND subject=$4 AND enabled FOR SHARE`, owner.Scope.TenantID, owner.Scope.Issuer, owner.Resource, q.Subject).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return authorization.ErrDenied
	}
	if err != nil {
		return authorization.ErrUnavailable
	}
	spec := domain.ObjectConsentSpec{AuthorizationHash: q.AuthorizationHash, ClientID: q.ClientID, Subject: q.Subject, Ceiling: q.Ceiling, PermissionVersion: version}
	// Finish every permission decision before the first display query. The root
	// and database mutation trigger guard inserts, updates and deletes together.
	for _, detail := range q.Ceiling.Snapshot().Details {
		var allowed bool
		err := tx.QueryRow(ctx, `SELECT actions @> $7::text[] FROM mayi_resource.permissions WHERE tenant_id=$1 AND issuer=$2 AND resource=$3 AND subject=$4 AND object_type=$5 AND identifier=$6`, owner.Scope.TenantID, owner.Scope.Issuer, owner.Resource, q.Subject, detail.Type, detail.Identifier, detail.Actions).Scan(&allowed)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !allowed {
			return authorization.ErrDenied
		}
		if err != nil {
			return authorization.ErrUnavailable
		}
	}
	// Every reader locks display rows in the same order; labels are separate
	// from authentication/ACL projections and contain no protected object body.
	details := q.Ceiling.Snapshot().Details
	slices.SortFunc(details, func(a, b grants.ObjectDetail) int {
		if a.Type < b.Type || a.Type == b.Type && a.Identifier < b.Identifier {
			return -1
		}
		if a.Type == b.Type && a.Identifier == b.Identifier {
			return 0
		}
		return 1
	})
	for _, detail := range details {
		var name string
		err := tx.QueryRow(ctx, `SELECT name FROM mayi_resource.labels WHERE tenant_id=$1 AND issuer=$2 AND resource=$3 AND object_type=$4 AND identifier=$5 FOR SHARE`, owner.Scope.TenantID, owner.Scope.Issuer, owner.Resource, detail.Type, detail.Identifier).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return authorization.ErrDenied
		}
		if err != nil {
			return authorization.ErrUnavailable
		}
		spec.Objects = append(spec.Objects, domain.ConsentObject{Type: detail.Type, Identifier: detail.Identifier, Name: name})
	}
	projection, err := domain.NewObjectConsentProjection(spec)
	if err != nil {
		return authorization.ErrUnavailable
	}
	// The read transaction stays open until the Mayi callback has committed.
	// No callback retries and no remote release/commit ambiguity are introduced.
	guard := &resourceGuard{store: a.store, scope: owner.Scope, tx: tx}
	if err := fn(context.WithValue(ctx, resourceGuardKey{}, guard), projection); err != nil {
		return err
	}
	if !guard.committed {
		return authorization.ErrUnavailable
	}
	return nil
}
