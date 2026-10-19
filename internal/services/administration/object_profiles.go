package administration

import (
	"context"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

// RegisterObjectProfile creates one immutable resource-owned type definition.
// This registers vocabulary, not current object permissions or a usable grant.
func (s *Service) RegisterObjectProfile(ctx context.Context, actor Actor, scope grants.Scope, resourceID string, input resources.ObjectProfileSpec) error {
	if err := authorize(actor, scope, "resources:write"); err != nil {
		return err
	}
	profile, err := resources.NewObjectProfile(input)
	if err != nil || input.Scope != scope || !resources.ValidID(resourceID) {
		return ErrInvalid
	}
	return s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		resource, err := tx.Resource(ctx, resourceID)
		if err != nil {
			return err
		}
		if resource.URI != input.Resource {
			return ErrInvalid
		}
		if err := tx.RegisterObjectProfile(ctx, resourceID, profile); err != nil {
			return err
		}
		return tx.Audit(ctx, "object_profile_registered", actor.ID, input.Type)
	})
}

func (s *Service) ObjectProfile(ctx context.Context, actor Actor, scope grants.Scope, resourceID, typeURI string) (resources.ObjectProfile, error) {
	if err := authorize(actor, scope, "resources:read"); err != nil {
		return resources.ObjectProfile{}, err
	}
	if !resources.ValidID(resourceID) || !resources.ValidObjectTypeURI(typeURI) {
		return resources.ObjectProfile{}, ErrInvalid
	}
	var result resources.ObjectProfile
	err := s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		var err error
		result, err = tx.ObjectProfile(ctx, resourceID, typeURI)
		return err
	})
	if err != nil {
		return resources.ObjectProfile{}, err
	}
	return result, nil
}
