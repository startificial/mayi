package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/startificial/mayi/internal/domain/audit"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/delivery"
	"time"
)

var _ delivery.Store = (*Store)(nil)

func (s *Store) ClaimEvent(ctx context.Context, scope grants.Scope, now time.Time, lease time.Duration) (audit.Delivery, bool, error) {
	if now.IsZero() || lease <= 0 || lease > time.Minute {
		return audit.Delivery{}, false, delivery.ErrUnavailable
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return audit.Delivery{}, false, err
	}
	defer rollback(tx)
	if err := scopeTransaction(ctx, tx, scope); err != nil {
		return audit.Delivery{}, false, err
	}
	d := audit.Delivery{Event: audit.Event{Scope: scope}}
	err = tx.QueryRow(ctx, `WITH candidate AS (
 SELECT o.tenant_id,o.event_id FROM mayi.outbox_events o JOIN mayi.tenants t USING(tenant_id)
 WHERE o.tenant_id=$1 AND t.issuer=$2 AND o.delivered_at IS NULL AND o.available_at<=$3
 ORDER BY o.event_id FOR UPDATE OF o SKIP LOCKED LIMIT 1
), claimed AS (
 UPDATE mayi.outbox_events o SET attempts=o.attempts+1,available_at=$4 FROM candidate c
 WHERE o.tenant_id=c.tenant_id AND o.event_id=c.event_id RETURNING o.event_id,o.attempts
) SELECT c.event_id,c.attempts,a.event_type,a.actor_id,a.object_ref,COALESCE(a.grant_id,''),COALESCE(a.issuance_id,''),a.created_at FROM claimed c
 JOIN mayi.audit_events a ON a.event_id=c.event_id AND a.tenant_id=$1`, scope.TenantID, scope.Issuer, now, now.Add(lease)).Scan(&d.Event.ID, &d.Attempt, &d.Event.Type, &d.Event.Actor, &d.Event.Object, &d.Event.GrantID, &d.Event.IssuanceID, &d.Event.OccurredAt)
	if err == pgx.ErrNoRows {
		return audit.Delivery{}, false, nil
	}
	if err != nil {
		return audit.Delivery{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return audit.Delivery{}, false, err
	}
	return d, true, nil
}
func (s *Store) CompleteEvent(ctx context.Context, d audit.Delivery, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := scopeTransaction(ctx, tx, d.Event.Scope); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE mayi.outbox_events o SET delivered_at=$5 FROM mayi.tenants t
 WHERE o.tenant_id=$1 AND t.tenant_id=o.tenant_id AND t.issuer=$2 AND o.event_id=$3 AND o.attempts=$4 AND o.delivered_at IS NULL AND o.available_at>$5`, d.Event.Scope.TenantID, d.Event.Scope.Issuer, d.Event.ID, d.Attempt, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return delivery.ErrUnavailable
	}
	return tx.Commit(ctx)
}
