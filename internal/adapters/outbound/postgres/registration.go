package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/authentication"
)

var _ administration.RegistrationAdmission = (*Store)(nil)

func (s *Store) AdmitRegistration(ctx context.Context, scope grants.Scope) (bool, error) {
	// One shared tenant counter is deliberately independent of caller-supplied
	// client IDs, tokens or proxy headers, so random identities cannot evade it.
	return s.ConsumeBudget(ctx, scope, authentication.Budget{Operation: "registration", Dimension: "client", Key: "tenant-registration", Limit: 60, WindowSeconds: 60})
}

func (m *management) RegistrationPolicy(ctx context.Context) (clients.RegistrationPolicy, error) {
	var p clients.RegistrationPolicy
	err := m.tx.QueryRow(ctx, `SELECT version,mode,resources,authorization_details_types,max_clients,access_token_seconds,require_initial_access FROM mayi.client_registration_policies WHERE tenant_id=$1`, m.scope.TenantID).Scan(&p.Version, &p.Mode, &p.Resources, &p.AuthorizationDetailsTypes, &p.MaxClients, &p.AccessTokenSeconds, &p.RequireInitialAccess)
	if errors.Is(err, pgx.ErrNoRows) {
		return clients.DefaultRegistrationPolicy(), nil
	}
	if err != nil {
		return clients.RegistrationPolicy{}, classifyManagement(err)
	}
	if !p.Valid() {
		return clients.RegistrationPolicy{}, administration.ErrUnavailable
	}
	return p, nil
}
func (m *management) SetRegistrationPolicy(ctx context.Context, p clients.RegistrationPolicy) error {
	if !p.Valid() {
		return administration.ErrInvalid
	}
	r, types := p.Resources, p.AuthorizationDetailsTypes
	if r == nil {
		r = []string{}
	}
	if types == nil {
		types = []string{}
	}
	_, err := m.tx.Exec(ctx, `INSERT INTO mayi.client_registration_policies(tenant_id,version,mode,resources,authorization_details_types,max_clients,access_token_seconds,require_initial_access) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id) DO UPDATE SET version=excluded.version,mode=excluded.mode,resources=excluded.resources,authorization_details_types=excluded.authorization_details_types,max_clients=excluded.max_clients,access_token_seconds=excluded.access_token_seconds,require_initial_access=excluded.require_initial_access`, m.scope.TenantID, p.Version, p.Mode, r, types, p.MaxClients, p.AccessTokenSeconds, p.RequireInitialAccess)
	return classifyManagement(err)
}
func (m *management) DynamicClientCount(ctx context.Context) (int, error) {
	var count int
	err := m.tx.QueryRow(ctx, `SELECT count(*) FROM mayi.dynamic_clients WHERE tenant_id=$1`, m.scope.TenantID).Scan(&count)
	return count, classifyManagement(err)
}
func (m *management) MarkDynamicClient(ctx context.Context, id string) error {
	_, err := m.tx.Exec(ctx, `INSERT INTO mayi.dynamic_clients(tenant_id,client_id) VALUES($1,$2)`, m.scope.TenantID, id)
	return classifyManagement(err)
}
