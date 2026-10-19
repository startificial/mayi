package postgres

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/delivery"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ delivery.SecurityStore = (*Store)(nil)

func (s *Store) RecordDenied(ctx context.Context, scope grants.Scope, operation string, status int) error {
	return s.Run(ctx, scope, func(raw tokens.Transaction) error {
		tx := raw.(*transaction).tx
		_, err := tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,object_ref,status_code) VALUES($1,'http_request_denied',$2,$3)`, scope.TenantID, operation, status)
		return err
	})
}
func (s *Store) RecordInactive(ctx context.Context, caller tokens.StatusCaller, resource string) error {
	return s.Run(ctx, caller.Scope, func(raw tokens.Transaction) error {
		tx := raw.(*transaction)
		if err := statusCaller(ctx, tx, caller, true, resource); err != nil {
			return err
		}
		_, err := tx.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id,client_id,resource) VALUES($1,'introspection_inactive',$2,$2,$3)`, caller.Scope.TenantID, caller.ClientID, resource)
		return err
	})
}
