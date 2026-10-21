package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/clients"
	"github.com/startificial/mayi/internal/services/tokens"
	"time"
)

var _ clients.Store = (*Store)(nil)

func (s *Store) Authentication(ctx context.Context, scope grants.Scope, id string) (clients.Authentication, error) {
	var result clients.Authentication
	err := s.Run(ctx, scope, func(raw tokens.Transaction) error {
		t := raw.(*transaction)
		m := &management{tx: t.tx, scope: scope, version: t.version}
		var err error
		result.Client, err = m.Client(ctx, id)
		if errors.Is(err, administration.ErrNotFound) {
			return clients.ErrDenied
		}
		if err != nil {
			return clients.ErrUnavailable
		}
		if !result.Client.Enabled {
			return clients.ErrDenied
		}
		var jwks []byte
		if err := t.tx.QueryRow(ctx, `SELECT auth_version,jwks,jwks_uri FROM mayi.clients WHERE tenant_id=$1 AND client_id=$2 AND enabled`, scope.TenantID, id).Scan(&result.Version, &jwks, &result.JWKSURI); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return clients.ErrUnavailable
			}
			return clients.ErrDenied
		}
		if len(jwks) > 0 && string(jwks) != "null" {
			result.JWKS = string(jwks)
		}
		rows, err := t.tx.Query(ctx, `SELECT secret_hash,expires_at FROM mayi.client_secrets WHERE tenant_id=$1 AND client_id=$2 AND expires_at>clock_timestamp() ORDER BY expires_at DESC LIMIT 3`, scope.TenantID, id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var h clients.SecretHash
			if err := rows.Scan(&h.Hash, &h.ExpiresAt); err != nil {
				rows.Close()
				return err
			}
			result.SecretHashes = append(result.SecretHashes, h)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(result.SecretHashes) > 2 {
			return clients.ErrUnavailable
		}
		rows, err = t.tx.Query(ctx, `SELECT DISTINCT s.name FROM mayi.resource_scopes s JOIN mayi.client_resources c USING(tenant_id,resource_id) WHERE c.tenant_id=$1 AND c.client_id=$2 AND c.resource_id=ANY($3::text[]) ORDER BY s.name LIMIT 129`, scope.TenantID, id, result.Client.Resources)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			result.Scopes = append(result.Scopes, name)
		}
		err = rows.Err()
		rows.Close()
		if len(result.Scopes) > 128 {
			return clients.ErrUnavailable
		}
		if err != nil {
			return err
		}
		rows, err = t.tx.Query(ctx, `SELECT r.uri FROM mayi.client_resources c JOIN mayi.resources r USING(tenant_id,resource_id) WHERE c.tenant_id=$1 AND c.client_id=$2 AND c.resource_id=ANY($3::text[]) LIMIT 33`, scope.TenantID, id, result.Client.Resources)
		if err != nil {
			return err
		}
		for rows.Next() {
			var uri string
			if err := rows.Scan(&uri); err != nil {
				rows.Close()
				return err
			}
			result.Resources = append(result.Resources, uri)
		}
		err = rows.Err()
		rows.Close()
		if len(result.Resources) > 32 {
			return clients.ErrUnavailable
		}
		return err
	})
	return result, err
}
func (s *Store) ConsumeAssertion(ctx context.Context, scope grants.Scope, client, id string, expiry time.Time) error {
	return s.Run(ctx, scope, func(raw tokens.Transaction) error {
		t := raw.(*transaction)
		tag, err := t.tx.Exec(ctx, `INSERT INTO mayi.proof_replays VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, scope.TenantID, "client-assertion:"+client, id, expiry)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return clients.ErrDenied
		}
		return nil
	})
}
func (s *Store) RotateSecret(ctx context.Context, scope grants.Scope, id, hash string, expiry, overlap time.Time, actor string) error {
	return s.RunManagement(ctx, scope, func(raw administration.Transaction) error {
		t := raw.(*management)
		var method string
		if err := t.tx.QueryRow(ctx, `SELECT auth_method FROM mayi.clients WHERE tenant_id=$1 AND client_id=$2 AND enabled FOR UPDATE`, scope.TenantID, id).Scan(&method); err != nil || method != "client_secret_basic" {
			return clients.ErrDenied
		}
		if _, err := t.tx.Exec(ctx, `UPDATE mayi.client_secrets SET expires_at=CASE WHEN secret_hash=(SELECT secret_hash FROM mayi.client_secrets WHERE tenant_id=$1 AND client_id=$2 ORDER BY created_at DESC LIMIT 1) THEN LEAST(expires_at,$3) ELSE LEAST(expires_at,clock_timestamp()) END WHERE tenant_id=$1 AND client_id=$2`, scope.TenantID, id, overlap); err != nil {
			return err
		}
		if _, err := t.tx.Exec(ctx, `INSERT INTO mayi.client_secrets(tenant_id,client_id,secret_hash,expires_at) VALUES($1,$2,$3,$4)`, scope.TenantID, id, hash, expiry); err != nil {
			return err
		}
		if _, err := t.tx.Exec(ctx, `UPDATE mayi.clients SET auth_version=auth_version+1 WHERE tenant_id=$1 AND client_id=$2`, scope.TenantID, id); err != nil {
			return err
		}
		if _, err := t.tx.Exec(ctx, `UPDATE mayi.tenants SET policy_version=policy_version+1 WHERE tenant_id=$1`, scope.TenantID); err != nil {
			return err
		}
		return t.Audit(ctx, "client_secret_rotated", actor, id)
	})
}

// SetClientKeys is an adapter-local persistence helper used by the registry
// mutation below; it never accepts a URL from a token or assertion header.
func setClientKeys(ctx context.Context, tx pgx.Tx, scope grants.Scope, id, inline, uri string) error {
	var value any
	if inline != "" {
		if !json.Valid([]byte(inline)) {
			return clients.ErrDenied
		}
		value = inline
	}
	_, err := tx.Exec(ctx, `UPDATE mayi.clients SET jwks=$3::jsonb,jwks_uri=$4,auth_version=auth_version+1 WHERE tenant_id=$1 AND client_id=$2`, scope.TenantID, id, value, uri)
	return err
}

func (s *Store) ConfigureKeys(ctx context.Context, scope grants.Scope, id, inline, uri, actor string) error {
	return s.RunManagement(ctx, scope, func(raw administration.Transaction) error {
		t := raw.(*management)
		var method string
		if err := t.tx.QueryRow(ctx, `SELECT auth_method FROM mayi.clients WHERE tenant_id=$1 AND client_id=$2 AND enabled FOR UPDATE`, scope.TenantID, id).Scan(&method); err != nil || method != "private_key_jwt" {
			return clients.ErrDenied
		}
		if err := setClientKeys(ctx, t.tx, scope, id, inline, uri); err != nil {
			return err
		}
		if _, err := t.tx.Exec(ctx, `UPDATE mayi.tenants SET policy_version=policy_version+1 WHERE tenant_id=$1`, scope.TenantID); err != nil {
			return err
		}
		return t.Audit(ctx, "client_keys_configured", actor, id)
	})
}
