package postgres

import (
	"context"
	"github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/tokens"
)

var _ tokens.MachinePolicyStore = (*Store)(nil)
var _ tokens.MachinePolicyManagement = (*machinePolicyManagement)(nil)

type machinePolicyManagement struct{ management *management }

func (s *Store) ManageMachinePolicy(ctx context.Context, scope grants.Scope, fn func(tokens.MachinePolicyManagement) error) error {
	var callbackErr error
	err := s.RunManagement(ctx, scope, func(tx administration.Transaction) error {
		callbackErr = fn(&machinePolicyManagement{tx.(*management)})
		return callbackErr
	})
	if callbackErr != nil {
		return callbackErr
	}
	return err
}
func (m *machinePolicyManagement) Registration(ctx context.Context, client, resource string) (authorization.Registration, error) {
	return registration(ctx, m.management.tx, m.management.scope, m.management.version, client, resource)
}
func (m *machinePolicyManagement) SetMachineAuthorization(ctx context.Context, input tokens.MachineAuthorization, remove bool, actor string) error {
	tx, scope := m.management.tx, m.management.scope
	event := "machine_authorization_configured"
	if remove {
		if _, err := tx.Exec(ctx, `DELETE FROM mayi.machine_authorizations WHERE tenant_id=$1 AND client_id=$2 AND resource=$3`, scope.TenantID, input.ClientID, input.Resource); err != nil {
			return err
		}
		event = "machine_authorization_removed"
	} else {
		objects, err := encodeObjectCeiling(input.Objects, scope, input.Resource)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mayi.machine_authorizations VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,client_id,resource) DO UPDATE SET scopes=excluded.scopes,object_ceiling=excluded.object_ceiling`, scope.TenantID, input.ClientID, input.Resource, input.Scopes, objects); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE mayi.tenants SET policy_version=policy_version+1 WHERE tenant_id=$1`, scope.TenantID); err != nil {
		return err
	}
	return m.management.Audit(ctx, event, actor, input.ClientID+" "+input.Resource)
}
