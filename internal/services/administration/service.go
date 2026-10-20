// Package administration owns tenant-scoped management and policy decisions.
package administration

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	"slices"
	"time"
)

var ErrDenied = errors.New("management operation denied")
var ErrInvalid = errors.New("invalid management input")
var ErrConflict = errors.New("management state conflict")
var ErrNotFound = errors.New("management object not found")
var ErrUnavailable = errors.New("management unavailable")

// Actor comes only from the authenticated adapter's trusted credential registry.
// Its scope and permissions must never be decoded from the request body.
type Actor struct {
	ID          string
	Scope       grants.Scope
	Permissions []string
}
type Service struct {
	store Store
	keys  KeyCatalog
	clock Clock
}

func New(store Store, keys KeyCatalog, clock Clock) (*Service, error) {
	if store == nil || keys == nil || clock == nil {
		return nil, ErrUnavailable
	}
	return &Service{store: store, keys: keys, clock: clock}, nil
}
func authorize(actor Actor, scope grants.Scope, action string) error {
	if !scope.Valid() || actor.Scope != scope || !resources.ValidID(actor.ID) || !slices.Contains(actor.Permissions, action) {
		return ErrDenied
	}
	return nil
}

// ProvisionTenant is shared by local operator interfaces. The HTTP credential
// registry deliberately cannot grant tenants:provision.
func (s *Service) ProvisionTenant(ctx context.Context, actor Actor, scope grants.Scope, version int) error {
	if err := authorize(actor, scope, "tenants:provision"); err != nil {
		return err
	}
	if version < 1 {
		return ErrInvalid
	}
	key, err := s.keys.PublicKey(ctx, scope, version)
	if err != nil || key.Version != version || key.ID == "" || key.X == "" || key.Y == "" {
		return ErrInvalid
	}
	return s.store.ProvisionTenant(ctx, scope, key, policy.DefaultTenant(), actor.ID)
}
func (s *Service) Policy(ctx context.Context, actor Actor, scope grants.Scope) (policy.Tenant, error) {
	if err := authorize(actor, scope, "policy:read"); err != nil {
		return policy.Tenant{}, err
	}
	var result policy.Tenant
	err := s.store.RunManagement(ctx, scope, func(tx Transaction) error { var err error; result, err = tx.Policy(ctx); return err })
	return result, err
}
func (s *Service) SetPolicy(ctx context.Context, actor Actor, scope grants.Scope, input policy.Tenant) (policy.Tenant, error) {
	if err := authorize(actor, scope, "policy:write"); err != nil {
		return policy.Tenant{}, err
	}
	if !input.Valid() {
		return policy.Tenant{}, ErrInvalid
	}
	err := s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		old, err := tx.Policy(ctx)
		if err != nil {
			return err
		}
		if old.Version != input.Version {
			return ErrConflict
		}
		input.Version++
		if err := tx.SetPolicy(ctx, input); err != nil {
			return err
		}
		return tx.Audit(ctx, "policy_updated", actor.ID, "policy")
	})
	if err != nil {
		return policy.Tenant{}, err
	}
	return input, nil
}
func (s *Service) CreateResource(ctx context.Context, actor Actor, scope grants.Scope, input resources.Resource) error {
	if err := authorize(actor, scope, "resources:write"); err != nil {
		return err
	}
	if !input.Valid() {
		return ErrInvalid
	}
	return s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		p, err := tx.Policy(ctx)
		if err != nil {
			return err
		}
		if input.AccessTokenSeconds > p.MaxAccessTokenSeconds || p.RequireBinding && !input.RequireBinding {
			return ErrInvalid
		}
		if err := tx.CreateResource(ctx, input); err != nil {
			return err
		}
		return tx.Audit(ctx, "resource_created", actor.ID, input.ID)
	})
}
func (s *Service) Resource(ctx context.Context, actor Actor, scope grants.Scope, id string) (resources.Resource, error) {
	if err := authorize(actor, scope, "resources:read"); err != nil {
		return resources.Resource{}, err
	}
	if !resources.ValidID(id) {
		return resources.Resource{}, ErrInvalid
	}
	var result resources.Resource
	err := s.store.RunManagement(ctx, scope, func(tx Transaction) error { var err error; result, err = tx.Resource(ctx, id); return err })
	return result, err
}
func (s *Service) CreateClient(ctx context.Context, actor Actor, scope grants.Scope, input clients.Client) error {
	if err := authorize(actor, scope, "clients:write"); err != nil {
		return err
	}
	if !input.Valid() {
		return ErrInvalid
	}
	return s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		if err := validateClientRegistration(ctx, tx, scope, input); err != nil {
			return err
		}
		if err := tx.CreateClient(ctx, input); err != nil {
			return err
		}
		return tx.Audit(ctx, "client_created", actor.ID, input.ID)
	})
}
func (s *Service) Client(ctx context.Context, actor Actor, scope grants.Scope, id string) (clients.Client, error) {
	if err := authorize(actor, scope, "clients:read"); err != nil {
		return clients.Client{}, err
	}
	if !clients.ValidClientID(id) {
		return clients.Client{}, ErrInvalid
	}
	var result clients.Client
	err := s.store.RunManagement(ctx, scope, func(tx Transaction) error { var err error; result, err = tx.Client(ctx, id); return err })
	return result, err
}
func (s *Service) PublishKey(ctx context.Context, actor Actor, scope grants.Scope, version int) error {
	if err := authorize(actor, scope, "keys:write"); err != nil {
		return err
	}
	if version < 1 {
		return ErrInvalid
	}
	key, err := s.keys.PublicKey(ctx, scope, version)
	if err != nil {
		return ErrInvalid
	}
	return s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		if err := tx.PublishKey(ctx, key, s.clock.Now()); err != nil {
			return err
		}
		return tx.Audit(ctx, "key_published", actor.ID, key.ID)
	})
}
func (s *Service) ActivateKey(ctx context.Context, actor Actor, scope grants.Scope, version int) error {
	if err := authorize(actor, scope, "keys:write"); err != nil {
		return err
	}
	if version < 1 {
		return ErrInvalid
	}
	// The key must also be loaded and verified by this process before activation.
	key, err := s.keys.PublicKey(ctx, scope, version)
	if err != nil {
		return ErrInvalid
	}
	return s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		if err := tx.ActivateKey(ctx, version, s.clock.Now(), time.Minute); err != nil {
			return err
		}
		return tx.Audit(ctx, "key_activated", actor.ID, key.ID)
	})
}

// validateClientRegistration is shared by operator and public registration.
// It runs after admission and inside the tenant management lock.
func validateClientRegistration(ctx context.Context, tx Transaction, scope grants.Scope, input clients.Client) error {
	p, err := tx.Policy(ctx)
	if err != nil {
		return err
	}
	if input.AccessTokenSeconds > p.MaxAccessTokenSeconds {
		return ErrInvalid
	}
	registeredResources := make(map[string]resources.Resource, len(input.Resources))
	for _, id := range input.Resources {
		r, err := tx.Resource(ctx, id)
		if err != nil {
			return err
		}
		if input.AccessTokenSeconds > r.AccessTokenSeconds {
			return ErrInvalid
		}
		registeredResources[r.URI] = r
	}
	for _, typ := range input.AuthorizationDetailsTypes {
		profile, err := tx.ClientObjectProfile(ctx, typ, input.Resources)
		if errors.Is(err, ErrNotFound) {
			return ErrInvalid
		}
		if err != nil {
			return err
		}
		definition := profile.Snapshot()
		if definition.Scope != scope || definition.Type != typ || !input.AllowsObjectProfile(registeredResources[definition.Resource], profile) {
			return ErrInvalid
		}
	}
	return nil
}
