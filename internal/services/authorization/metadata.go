package authorization

import (
	"context"
	"errors"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/clients"
)

func (s *Service) refreshMetadata(ctx context.Context, workflow domain.Transaction) error {
	r := workflow.Snapshot().Request
	if _, cimd := clients.MetadataURL(r.ClientID); !cimd {
		return nil
	}
	if s.metadata == nil {
		return ErrDenied
	}
	c, err := s.metadata.ResolveClient(ctx, r.TenantIssuer, r.ClientID, true)
	if err != nil {
		if errors.Is(err, clients.ErrMetadataDenied) {
			return ErrDenied
		}
		return ErrUnavailable
	}
	if !r.PinnedMetadata() || c.MetadataDigest != r.ClientMetadataDigest {
		return ErrDenied
	}
	return nil
}
func (s *Service) denyMetadataConsent(ctx context.Context, p AccessProof, actor Principal, candidate domain.Transaction) (DecisionResult, error) {
	if err := s.refreshMetadata(ctx, candidate); err != nil {
		return DecisionResult{}, err
	}
	var result DecisionResult
	err := s.store.RunAuthorization(ctx, p.TenantIssuer, func(tx Transaction) error {
		workflow, current, err := s.loadConsent(ctx, tx, p, actor, true)
		if err != nil {
			return err
		}
		if !workflow.Snapshot().Request.Equal(candidate.Snapshot().Request) {
			return ErrDenied
		}
		workflow, err = s.bindConsent(ctx, tx, p, actor, workflow)
		if err != nil {
			return err
		}
		result, err = s.completeDecision(ctx, tx, workflow, current, actor, false, domain.ObjectConsentProjection{}, domain.ObjectConsentProjection{})
		return err
	})
	if err != nil {
		return DecisionResult{}, classified(err)
	}
	return result, nil
}
