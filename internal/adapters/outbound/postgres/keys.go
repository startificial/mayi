package postgres

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.ActiveKeyReader = (*Store)(nil)

func (s *Store) ActiveSigningKey(ctx context.Context, scope grants.Scope) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, tokens.ErrUnavailable
	}
	defer rollback(tx)
	if err := scopeTransaction(ctx, tx, scope); err != nil {
		return 0, tokens.ErrUnavailable
	}
	var version int
	err = tx.QueryRow(ctx, `SELECT k.version FROM mayi.signing_keys k JOIN mayi.tenants t USING(tenant_id) WHERE k.tenant_id=$1 AND t.issuer=$2 AND k.active`, scope.TenantID, scope.Issuer).Scan(&version)
	if err != nil {
		return 0, tokens.ErrUnavailable
	}
	return version, nil
}
