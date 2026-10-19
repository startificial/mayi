package authorization

import (
	"context"
	"time"

	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

type PushedResult struct {
	Reference string
	ExpiresAt time.Time
}

// PushedProof is reference possession and declared public-client correlation,
// not confidential-client authentication or user authority. Adapters hash the
// raw reference and obtain tenant context from configured issuer routing.
type PushedProof struct {
	TenantIssuer                                grants.Scope
	ClientID, ReferenceHash, BrowserBindingHash string
}

func (p PushedProof) Valid() bool {
	return p.TenantIssuer.Valid() && resources.ValidID(p.ClientID) && domain.ValidHandleHash(p.ReferenceHash) && domain.ValidHandleHash(p.BrowserBindingHash)
}

// Push supports the currently registered public web-client model only. Future
// confidential clients require their registered authentication policy first.
// No HTTP endpoint exposes this operation while object consent remains gated.
func (s *Service) Push(ctx context.Context, request domain.Request) (PushedResult, error) {
	return s.push(ctx, request, 0)
}
func (s *Service) PushAuthenticated(ctx context.Context, request domain.Request, version uint64) (PushedResult, error) {
	if version == 0 {
		return PushedResult{}, ErrDenied
	}
	return s.push(ctx, request, version)
}
func (s *Service) push(ctx context.Context, request domain.Request, authVersion uint64) (PushedResult, error) {
	if !request.Valid() || request.ObjectCeiling.IsZero() || len(request.State) < 16 {
		return PushedResult{}, ErrInvalid
	}
	now := s.clock.Now()
	if now.IsZero() {
		return PushedResult{}, ErrUnavailable
	}
	var result PushedResult
	err := s.store.RunAuthorization(ctx, request.TenantIssuer, func(tx Transaction) error {
		current, err := tx.Registration(ctx, request.ClientID, request.ResourceURI)
		if err != nil {
			return err
		}
		if current.Client.Machine || authVersion != 0 && current.Client.AuthenticationVersion != authVersion || !request.MatchesObjectRegistration(current) {
			return ErrInvalid
		}
		m, err := s.material.NewAuthorizationMaterial(ctx)
		if err != nil || !validMaterial(m) {
			return ErrUnavailable
		}
		p, err := domain.NewPushed(domain.PushedSpec{ID: m.ID, ReferenceHash: m.Hash, Request: request, PolicyVersion: current.Policy.Version, CreatedAt: now, ExpiresAt: now.Add(domain.PushedLifetime)})
		if err != nil {
			return ErrInvalid
		}
		if err := tx.CreatePushed(ctx, p); err != nil {
			return err
		}
		result = PushedResult{Reference: m.Secret, ExpiresAt: p.Snapshot().ExpiresAt}
		return nil
	})
	if err != nil {
		return PushedResult{}, classified(err)
	}
	return result, nil
}

func (s *Service) BeginPushed(ctx context.Context, proof PushedProof) (BeginResult, error) {
	if !proof.Valid() {
		return BeginResult{}, ErrDenied
	}
	var result BeginResult
	err := s.store.RunAuthorization(ctx, proof.TenantIssuer, func(tx Transaction) error {
		if err := tx.AuthorizePushed(ctx, proof, s.clock.Now()); err != nil {
			return err
		}
		pushed, err := tx.Pushed(ctx, proof.ReferenceHash)
		if err != nil {
			return err
		}
		p := pushed.Snapshot()
		if !pushed.ActiveAt(s.clock.Now()) || p.ReferenceHash != proof.ReferenceHash || p.Request.TenantIssuer != proof.TenantIssuer || p.Request.ClientID != proof.ClientID {
			return ErrDenied
		}
		current, err := tx.Registration(ctx, proof.ClientID, p.Request.ResourceURI)
		if err != nil {
			return err
		}
		if p.PolicyVersion != current.Policy.Version || !p.Request.MatchesObjectRegistration(current) {
			return ErrDenied
		}
		handle, err := s.material.NewAuthorizationMaterial(ctx)
		if err != nil || !validMaterial(handle) {
			return ErrUnavailable
		}
		csrf, err := s.material.NewAuthorizationMaterial(ctx)
		if err != nil || !validMaterial(csrf) {
			return ErrUnavailable
		}
		now := s.clock.Now()
		next, workflow, err := pushed.Begin(handle.ID, handle.Hash, proof.BrowserBindingHash, csrf.Hash, now)
		if err != nil {
			return ErrDenied
		}
		if err := tx.ConsumePushed(ctx, next, workflow, now); err != nil {
			return err
		}
		result = BeginResult{Handle: handle.Secret, CSRFToken: csrf.Secret, ExpiresAt: workflow.Snapshot().ExpiresAt}
		return nil
	})
	if err != nil {
		return BeginResult{}, classified(err)
	}
	return result, nil
}
