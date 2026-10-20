package postgres

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
	"time"
)

var _ tokens.ProofNonceStore = (*Store)(nil)

func (s *Store) ValidProofNonce(ctx context.Context, scope grants.Scope, purpose, target, thumb, hash string) (bool, error) {
	valid := false
	err := s.Run(ctx, scope, func(raw tokens.Transaction) error {
		t := raw.(*transaction)
		return t.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.proof_nonces WHERE tenant_id=$1 AND purpose=$2 AND target=$3 AND thumbprint=$4 AND nonce_hash=$5 AND expires_at>clock_timestamp())`, scope.TenantID, purpose, target, thumb, hash).Scan(&valid)
	})
	return valid, err
}
func (s *Store) RememberProofNonce(ctx context.Context, scope grants.Scope, purpose, target, thumb, hash string, expiry time.Time) error {
	return s.Run(ctx, scope, func(raw tokens.Transaction) error {
		t := raw.(*transaction)
		if _, err := t.tx.Exec(ctx, `SELECT mayi.cleanup_expired_proof_state()`); err != nil {
			return err
		}
		tag, err := t.tx.Exec(ctx, `INSERT INTO mayi.proof_nonces(tenant_id,purpose,target,thumbprint,nonce_hash,expires_at) SELECT $1,$2,$3,$4,$5,$6 WHERE $6>clock_timestamp() AND $6<=clock_timestamp()+interval '65 seconds'`, scope.TenantID, purpose, target, thumb, hash, expiry)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return tokens.ErrUnavailable
		}
		return nil
	})
}
