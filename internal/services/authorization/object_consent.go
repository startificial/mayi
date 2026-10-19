package authorization

import (
	"context"

	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/resources"
)

// Acquire resource permission before opening the final Mayi transaction. The
// initial authorized read has already committed without binding or other effects.
func (s *Service) prepareObjectConsent(ctx context.Context, proof AccessProof, actor Principal, candidate domain.Transaction) (Consent, error) {
	before := candidate.Snapshot()
	query := ObjectConsentQuery{TenantIssuer: actor.TenantIssuer, Subject: actor.Subject, AuthorizationHash: before.HandleHash, ClientID: before.Request.ClientID, Ceiling: before.Request.ObjectCeiling}
	var result Consent
	calls := 0
	var callbackErr error
	err := s.objects.WithObjectConsent(ctx, query, func(projection domain.ObjectConsentProjection) error {
		calls++
		if calls != 1 {
			callbackErr = ErrUnavailable
			return callbackErr
		}
		result, callbackErr = s.guardedObjectConsent(ctx, proof, actor, candidate, projection)
		return callbackErr
	})
	if err != nil {
		return Consent{}, classified(err)
	}
	if callbackErr != nil {
		return Consent{}, classified(callbackErr)
	}
	if calls != 1 || result.ClientID == "" {
		return Consent{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) guardedObjectConsent(ctx context.Context, proof AccessProof, actor Principal, candidate domain.Transaction, projection domain.ObjectConsentProjection) (Consent, error) {
	if !projection.Matches(candidate, actor.Subject) {
		return Consent{}, ErrDenied
	}
	before := candidate.Snapshot()
	var result Consent
	err := s.store.RunAuthorization(ctx, proof.TenantIssuer, func(tx Transaction) error {
		workflow, current, err := s.loadConsent(ctx, tx, proof, actor, true)
		if err != nil {
			return err
		}
		after := workflow.Snapshot()
		if !projection.Matches(workflow, actor.Subject) || before.PolicyVersion != after.PolicyVersion || before.PushedRequestHash != after.PushedRequestHash || !before.Request.Equal(after.Request) {
			return ErrDenied
		}
		workflow, err = s.bindConsent(ctx, tx, proof, actor, workflow)
		if err != nil {
			return err
		}
		result = objectConsentView(workflow, current, projection)
		return nil
	})
	return result, err
}

func objectConsentView(workflow domain.Transaction, current domain.Registration, projection domain.ObjectConsentProjection) Consent {
	result := consentView(workflow, current)
	result.PermissionVersion = projection.Snapshot().PermissionVersion
	result.DecisionAvailable = false
	type reference struct{ typ, id string }
	labels := make(map[reference]string)
	for _, object := range projection.Snapshot().Objects {
		labels[reference{object.Type, object.Identifier}] = object.Name
	}
	vocabulary := make(map[string]map[string]resources.ObjectAction)
	for _, profile := range current.ObjectProfiles {
		definition := profile.Snapshot()
		actions := make(map[string]resources.ObjectAction)
		for _, action := range definition.Actions {
			actions[action.Name] = action
		}
		vocabulary[definition.Type] = actions
	}
	// Preserve request order; never display unrequested objects or actions.
	for _, detail := range workflow.Snapshot().Request.ObjectCeiling.Snapshot().Details {
		object := ConsentObject{Type: detail.Type, Identifier: detail.Identifier, Name: labels[reference{detail.Type, detail.Identifier}]}
		for _, action := range detail.Actions {
			object.Actions = append(object.Actions, vocabulary[detail.Type][action])
		}
		result.Objects = append(result.Objects, object)
	}
	return result
}

func consentView(workflow domain.Transaction, current domain.Registration) Consent {
	spec := workflow.Snapshot()
	result := Consent{ClientName: current.Client.Name, ClientID: current.Client.ID, ResourceName: current.Resource.Name, ResourceURI: current.Resource.URI, RedirectURI: spec.Request.RedirectURI, ExpiresAt: spec.ExpiresAt, DecisionAvailable: true}
	for _, name := range spec.Request.PermissionScopes {
		for _, permission := range current.Resource.Scopes {
			if name == permission.Name {
				result.PermissionScopes = append(result.PermissionScopes, resources.Scope{Name: permission.Name, Description: permission.Description})
				break
			}
		}
	}
	return result
}
