package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authentication"
)

var _ authentication.AdmissionStore = (*Store)(nil)

func (s *Store) ConsumeBudget(ctx context.Context, scope grants.Scope, b authentication.Budget) (bool, error) {
	if !scope.Valid() || b.Limit < 1 || b.Limit > 1000000 || b.WindowSeconds < 1 || b.WindowSeconds > 3600 || len(b.Key) > 2304 {
		return false, authentication.ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	if err := scopeTransaction(ctx, tx, scope); err != nil {
		return false, err
	}
	allowed, err := consumeBudget(ctx, tx, scope, b)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return allowed, nil
}
func (t *transaction) ConsumeBudget(ctx context.Context, scope grants.Scope, b authentication.Budget) (bool, error) {
	if t.scope != scope {
		return false, authentication.ErrDenied
	}
	return consumeBudget(ctx, t.tx, scope, b)
}
func (m *machineTransaction) ConsumeBudget(ctx context.Context, scope grants.Scope, b authentication.Budget) (bool, error) {
	return m.tx.ConsumeBudget(ctx, scope, b)
}
func consumeBudget(ctx context.Context, tx pgx.Tx, scope grants.Scope, b authentication.Budget) (bool, error) {
	digest := sha256.Sum256([]byte(scope.Issuer + "\x00" + b.Operation + "\x00" + b.Dimension + "\x00" + b.Key))
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.tenants WHERE tenant_id=$1 AND issuer=$2)`, scope.TenantID, scope.Issuer).Scan(&valid); err != nil || !valid {
		return false, authentication.ErrDenied
	}
	// Bounded opportunistic expiry work. It never resets a current window and
	// SKIP LOCKED keeps cleanup from blocking another replica's admission.
	if _, err := tx.Exec(ctx, `DELETE FROM mayi.request_budgets WHERE ctid IN(SELECT ctid FROM mayi.request_budgets WHERE tenant_id=$1 AND expires_at<clock_timestamp() ORDER BY expires_at LIMIT 32 FOR UPDATE SKIP LOCKED)`, scope.TenantID); err != nil {
		return false, err
	}
	var used int
	err := tx.QueryRow(ctx, `WITH stamp AS(SELECT date_bin(make_interval(secs=>$6),clock_timestamp(),timestamptz '1970-01-01') AS start)
 INSERT INTO mayi.request_budgets AS b(tenant_id,operation,dimension,key_hash,window_start,expires_at,used)
 SELECT $1,$2,$3,$4,start,start+make_interval(secs=>$6*2),1 FROM stamp
 ON CONFLICT(tenant_id,operation,dimension,key_hash) DO UPDATE
 SET window_start=excluded.window_start,expires_at=excluded.expires_at,used=CASE WHEN b.window_start<excluded.window_start THEN 1 ELSE b.used+1 END
 WHERE b.window_start<excluded.window_start OR b.window_start=excluded.window_start AND b.used<$5
 RETURNING used`, scope.TenantID, b.Operation, b.Dimension, hex.EncodeToString(digest[:]), b.Limit, b.WindowSeconds).Scan(&used)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
