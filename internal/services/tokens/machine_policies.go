package tokens

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"slices"
)

var ErrMachinePolicyDenied = errors.New("machine policy operation denied")

type MachineOperator struct {
	Scope       grants.Scope
	ID          string
	Permissions []string
}
type MachineAuthorization struct {
	ClientID, Resource string
	Scopes             []string
	Objects            grants.ObjectCeiling
}
type MachinePolicies struct {
	store MachinePolicyStore
	scope grants.Scope
}

func NewMachinePolicies(store MachinePolicyStore, scope grants.Scope) (*MachinePolicies, error) {
	if store == nil || !scope.Valid() {
		return nil, ErrUnavailable
	}
	return &MachinePolicies{store, scope}, nil
}
func (s *MachinePolicies) Configure(ctx context.Context, a MachineOperator, input MachineAuthorization, remove bool) error {
	if a.Scope != s.scope || !resources.ValidID(a.ID) || !slices.Contains(a.Permissions, "clients:write") {
		return ErrMachinePolicyDenied
	}
	if !clients.ValidClientID(input.ClientID) || !resources.ValidURI(input.Resource) {
		return ErrInvalidCredential
	}
	if !remove && (len(input.Scopes) == 0 || !grants.ValidScopes(input.Scopes) || !input.Objects.BoundTo(s.scope, input.Resource) || len(input.Objects.Snapshot().Details) == 0) {
		return ErrInvalidCredential
	}
	return s.store.ManageMachinePolicy(ctx, s.scope, func(tx MachinePolicyManagement) error {
		registration, err := tx.Registration(ctx, input.ClientID, input.Resource)
		if err != nil {
			return err
		}
		if !registration.Client.Machine || !registration.Client.Enabled {
			return ErrInvalidCredential
		}
		if !remove {
			for _, name := range input.Scopes {
				found := false
				for _, permission := range registration.Resource.Scopes {
					if permission.Name == name {
						found = true
						break
					}
				}
				if !found {
					return ErrInvalidCredential
				}
			}
			for _, profile := range registration.ObjectProfiles {
				if !registration.Client.AllowsObjectProfile(registration.Resource, profile) {
					return ErrInvalidCredential
				}
			}
			if _, err := resources.ValidateObjectRequest(s.scope, input.Resource, registration.ObjectProfiles, input.Objects.Snapshot().Details); err != nil {
				return ErrInvalidCredential
			}
		}
		return tx.SetMachineAuthorization(ctx, input, remove, a.ID)
	})
}
