package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres/migrations"
)

var ErrDatabaseConfiguration = errors.New("database requires reviewed migrations and a separate restricted runtime role")

// Check effective column grants too: inherited writes cannot be removed by
// revoking this login's table grants. The DBA must remove unsafe group grants.
const ledgerReadOnly = `NOT has_table_privilege($1,'mayi.schema_migrations','INSERT,UPDATE,DELETE,TRUNCATE')
 AND NOT has_any_column_privilege($1,'mayi.schema_migrations','INSERT,UPDATE')`

// Table-level REVOKE cannot remove inherited or separately granted column
// privileges. Fail closed unless the effective grants preserve this boundary.
const authorityLifecycleOnly = `NOT EXISTS(
 SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mayi' AND c.relname IN ('grants','credentials','refresh_families','issuances','proof_nonces','proof_replays')
 AND a.attnum>0 AND NOT a.attisdropped
 AND a.attname<>CASE WHEN c.relname='credentials' THEN 'consumed' ELSE 'revoked' END
 AND has_column_privilege($1,c.oid,a.attnum,'UPDATE'))
 AND NOT has_table_privilege($1,'mayi.proof_nonces','DELETE')
 AND NOT has_table_privilege($1,'mayi.proof_replays','DELETE')`

// ApplyMigrations requires an operator-supplied owner connection. Never run it
// automatically on server startup. A transaction lock serializes concurrent
// migrators; unknown/tampered history fails rather than adopting an old schema.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, runtimeRole string) error {
	if pool == nil || !regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`).MatchString(runtimeRole) {
		return ErrDatabaseConfiguration
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return ErrDatabaseConfiguration
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mayi.schema_migrations',0))`); err != nil {
		return err
	}
	var schemaExists, ledgerExists bool
	if err = tx.QueryRow(ctx, `SELECT to_regnamespace('mayi') IS NOT NULL,to_regclass('mayi.schema_migrations') IS NOT NULL`).Scan(&schemaExists, &ledgerExists); err != nil {
		return err
	}
	if schemaExists && !ledgerExists {
		return ErrDatabaseConfiguration
	}
	versions := migrationSources()
	if !schemaExists {
		if _, err = tx.Exec(ctx, versions[0]); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `CREATE TABLE mayi.schema_migrations(version integer PRIMARY KEY,sha256 text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); err != nil {
			return err
		}
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM mayi.schema_migrations`).Scan(&count); err != nil {
		return err
	}
	if count > len(versions) {
		return ErrDatabaseConfiguration
	}
	for n, source := range versions {
		digest := sha256.Sum256([]byte(source))
		expected := hex.EncodeToString(digest[:])
		var actual string
		err = tx.QueryRow(ctx, `SELECT sha256 FROM mayi.schema_migrations WHERE version=$1`, n+1).Scan(&actual)
		if err == nil {
			if actual != expected {
				return ErrDatabaseConfiguration
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) || n < count {
			return ErrDatabaseConfiguration
		}
		if schemaExists || n > 0 {
			if _, err = tx.Exec(ctx, source); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO mayi.schema_migrations(version,sha256) VALUES($1,$2)`, n+1, expected); err != nil {
			return err
		}
	}
	role := pgx.Identifier{runtimeRole}.Sanitize()
	// The DBA creates roles and credentials; Mayi never creates a superuser or
	// borrows the application's owner role. Existing unsafe roles are rejected.
	var safe bool
	err = tx.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND rolname<>current_user
 AND NOT pg_has_role(oid,(SELECT nspowner FROM pg_namespace WHERE nspname='mayi'),'MEMBER')
 FROM pg_roles WHERE rolname=$1`, runtimeRole).Scan(&safe)
	if err != nil || !safe {
		return ErrDatabaseConfiguration
	}
	for _, sql := range []string{
		`REVOKE ALL ON SCHEMA mayi FROM PUBLIC`,
		`GRANT USAGE ON SCHEMA mayi TO ` + role,
		`GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA mayi TO ` + role,
		`GRANT USAGE ON ALL SEQUENCES IN SCHEMA mayi TO ` + role,
		`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA mayi TO ` + role,
		`REVOKE ALL ON mayi.schema_migrations FROM ` + role,
		`GRANT SELECT ON mayi.schema_migrations TO ` + role,
		`REVOKE INSERT,UPDATE ON mayi.tenants,mayi.principal_memberships,mayi.browser_sessions FROM ` + role,
		`GRANT INSERT ON mayi.browser_sessions TO ` + role,
		`GRANT UPDATE(revoked) ON mayi.browser_sessions TO ` + role,
		`REVOKE INSERT,UPDATE ON mayi.external_identities FROM ` + role,
		`REVOKE UPDATE ON mayi.session_authentication,mayi.login_attempts FROM ` + role,
		`GRANT UPDATE(claimed_at,completed_at) ON mayi.login_attempts TO ` + role,
		`REVOKE UPDATE ON mayi.grant_revisions,mayi.authorization_transactions FROM ` + role,
		`REVOKE UPDATE ON mayi.resource_object_profiles FROM ` + role,
		`REVOKE UPDATE ON mayi.client_object_types FROM ` + role,
		`REVOKE UPDATE,DELETE ON mayi.proof_nonces,mayi.proof_replays FROM ` + role,
		`REVOKE UPDATE ON mayi.pushed_requests,mayi.authorization_object_presentations FROM ` + role,
		`GRANT UPDATE(consumed_at,authorization_hash) ON mayi.pushed_requests TO ` + role,
		`GRANT UPDATE(status,subject,grant_id,code_hash,decided_at,consent_session_hash,grant_revision) ON mayi.authorization_transactions TO ` + role,
		// Current lifecycle operations only consume credentials and revoke
		// authority. Identity, ancestry and ceilings need explicit future use cases.
		`REVOKE UPDATE ON mayi.grants,mayi.credentials,mayi.refresh_families,mayi.issuances FROM ` + role,
		`GRANT UPDATE(revoked) ON mayi.grants,mayi.refresh_families,mayi.issuances TO ` + role,
		`GRANT UPDATE(consumed) ON mayi.credentials TO ` + role,
		`GRANT UPDATE(policy_version) ON mayi.tenants TO ` + role,
		`REVOKE UPDATE ON mayi.audit_events,mayi.authorization_options,mayi.pushed_options FROM ` + role,
		`GRANT UPDATE(last_used_at) ON mayi.browser_sessions TO ` + role,
		`GRANT DELETE ON mayi.machine_authorizations,mayi.request_budgets TO ` + role,
	} {
		if _, err = tx.Exec(ctx, sql); err != nil {
			return err
		}
	}
	if err := tx.QueryRow(ctx, `SELECT `+ledgerReadOnly+` AND `+authorityLifecycleOnly, runtimeRole).Scan(&safe); err != nil || !safe {
		return ErrDatabaseConfiguration
	}
	return tx.Commit(ctx)
}

// ValidateRuntime is checked on every physical connection, including reconnects.
// Membership in an owner role is unsafe even when NOINHERIT is set.
func ValidateRuntime(ctx context.Context, conn *pgx.Conn, role string) error {
	if conn == nil || conn.Config().User != role {
		return ErrDatabaseConfiguration
	}
	var safe bool
	err := conn.QueryRow(ctx, `SELECT current_user=$1 AND session_user=$1 AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb
 AND NOT EXISTS(SELECT 1 FROM pg_roles p WHERE (p.rolsuper OR p.rolbypassrls OR p.rolcreaterole OR p.rolcreatedb) AND pg_has_role(r.oid,p.oid,'MEMBER'))
 AND NOT has_schema_privilege(current_user,'mayi','CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mayi' AND pg_has_role(r.oid,c.relowner,'MEMBER'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mayi' AND c.relkind='r' AND c.relname<>'schema_migrations' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR has_table_privilege(current_user,c.oid,'TRUNCATE')))
 AND `+ledgerReadOnly+` AND `+authorityLifecycleOnly+`
 FROM pg_roles r WHERE rolname=current_user`, role).Scan(&safe)
	if err != nil || !safe {
		return ErrDatabaseConfiguration
	}
	rows, err := conn.Query(ctx, `SELECT version,sha256 FROM mayi.schema_migrations ORDER BY version`)
	if err != nil {
		return ErrDatabaseConfiguration
	}
	defer rows.Close()
	for i, source := range migrationSources() {
		if !rows.Next() {
			return ErrDatabaseConfiguration
		}
		var version int
		var actual string
		if err := rows.Scan(&version, &actual); err != nil {
			return ErrDatabaseConfiguration
		}
		digest := sha256.Sum256([]byte(source))
		if version != i+1 || actual != hex.EncodeToString(digest[:]) {
			return ErrDatabaseConfiguration
		}
	}
	if rows.Next() || rows.Err() != nil {
		return ErrDatabaseConfiguration
	}
	return nil
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func migrationSources() []string {
	return []string{migrations.Initial, migrations.Foundation, migrations.Authorization, migrations.Authentication, migrations.ObjectCeilings, migrations.ObjectProfiles, migrations.ClientObjectTypes, migrations.Pushed, migrations.ObjectPresentations, migrations.Lifecycle, migrations.RequiredAuthority, migrations.RequestBudgets, migrations.Incremental, migrations.AuditContext, migrations.NativeClients, migrations.DPoP, migrations.ProofStatePrivileges}
}
