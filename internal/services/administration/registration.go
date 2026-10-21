package administration

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
)

var ErrRegistrationLimited = errors.New("registration capacity exhausted")
var ErrRegistrationQuota = errors.New("registration quota exhausted")
var ErrInitialAccess = errors.New("invalid registration credential")

type Registration struct {
	store       Store
	credentials RegistrationCredentials
	admission   RegistrationAdmission
	scope       grants.Scope
}

func NewRegistration(store Store, credentials RegistrationCredentials, admission RegistrationAdmission, scope grants.Scope) (*Registration, error) {
	if store == nil || credentials == nil || admission == nil || !scope.Valid() {
		return nil, ErrUnavailable
	}
	return &Registration{store, credentials, admission, scope}, nil
}

func (s *Service) RegistrationPolicy(ctx context.Context, actor Actor, scope grants.Scope) (clients.RegistrationPolicy, error) {
	if err := authorize(actor, scope, "clients:read"); err != nil {
		return clients.RegistrationPolicy{}, err
	}
	var result clients.RegistrationPolicy
	err := s.store.RunManagement(ctx, scope, func(tx Transaction) error { var err error; result, err = tx.RegistrationPolicy(ctx); return err })
	if err != nil {
		return clients.RegistrationPolicy{}, err
	}
	return result, nil
}

func (s *Service) SetRegistrationPolicy(ctx context.Context, actor Actor, scope grants.Scope, p clients.RegistrationPolicy) (clients.RegistrationPolicy, error) {
	if err := authorize(actor, scope, "clients:write"); err != nil {
		return clients.RegistrationPolicy{}, err
	}
	if !p.Valid() {
		return clients.RegistrationPolicy{}, ErrInvalid
	}
	err := s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		old, err := tx.RegistrationPolicy(ctx)
		if err != nil {
			return err
		}
		if old.Version != p.Version {
			return ErrConflict
		}
		if p.Mode == "open" {
			metadataPolicy, err := tx.MetadataPolicy(ctx)
			if err != nil {
				return err
			}
			if !metadataPolicy.AllowsDynamicRegistration() {
				return ErrDenied
			}
			// Validate the configured admission ceiling through the same registry
			// rules used for each client before publishing the policy.
			c, ok := p.Client("registration", clients.PublicRegistration{Name: "Registration", RedirectURIs: []string{"https://registration.example/callback"}, Resources: p.Resources, AuthorizationDetailsTypes: p.AuthorizationDetailsTypes})
			if !ok {
				return ErrInvalid
			}
			if err := validateClientRegistration(ctx, tx, scope, c); err != nil {
				return err
			}
		}
		p.Version++
		if err := tx.SetRegistrationPolicy(ctx, p); err != nil {
			return err
		}
		return tx.Audit(ctx, "client_registration_policy_updated", actor.ID, "registration")
	})
	if err != nil {
		return clients.RegistrationPolicy{}, err
	}
	return p, nil
}

func (s *Registration) Register(ctx context.Context, scope grants.Scope, initialAccess string, input clients.PublicRegistration) (clients.Client, error) {
	if scope != s.scope {
		return clients.Client{}, ErrDenied
	}
	allowed, err := s.admission.AdmitRegistration(ctx, scope)
	if err != nil {
		return clients.Client{}, ErrUnavailable
	}
	if !allowed {
		return clients.Client{}, ErrRegistrationLimited
	}
	// Credential verification is bounded and local. A supplied bad credential
	// never silently becomes an anonymous request, even under open admission.
	verified, err := s.credentials.InitialAccess(ctx, scope, initialAccess)
	if err != nil {
		return clients.Client{}, ErrUnavailable
	}
	if initialAccess != "" && !verified {
		return clients.Client{}, ErrInitialAccess
	}
	id, err := s.credentials.NewClientID(ctx, scope)
	if err != nil || !clients.ValidClientID(id) {
		return clients.Client{}, ErrUnavailable
	}
	var result clients.Client
	err = s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		p, err := tx.RegistrationPolicy(ctx)
		if err != nil {
			return err
		}
		if !p.Valid() {
			return ErrUnavailable
		}
		if p.Mode != "open" {
			return ErrDenied
		}
		metadataPolicy, err := tx.MetadataPolicy(ctx)
		if err != nil {
			return err
		}
		if !metadataPolicy.AllowsDynamicRegistration() {
			return ErrDenied
		}
		if p.RequireInitialAccess && !verified {
			return ErrInitialAccess
		}
		var ok bool
		result, ok = p.Client(id, input)
		if !ok {
			return ErrInvalid
		}
		count, err := tx.DynamicClientCount(ctx)
		if err != nil {
			return err
		}
		if count >= p.MaxClients {
			return ErrRegistrationQuota
		}
		if err := validateClientRegistration(ctx, tx, scope, result); err != nil {
			return err
		}
		if err := tx.CreateClient(ctx, result); err != nil {
			return err
		}
		if err := tx.MarkDynamicClient(ctx, result.ID); err != nil {
			return err
		}
		return tx.Audit(ctx, "public_client_registered", result.ID, result.ID)
	})
	if err != nil {
		return clients.Client{}, err
	}
	return result, nil
}
