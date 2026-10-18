// Package authorization orchestrates browser consent and atomic code creation.
package authorization

import (
	"context"
	"errors"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"time"
)

var ErrDenied = errors.New("authorization denied")
var ErrInvalid = errors.New("invalid authorization request")
var ErrUnavailable = errors.New("authorization unavailable")

type Material struct{ ID, Secret, Hash string }
type AccessProof struct {
	TenantIssuer                                                 grants.Scope
	SessionHash, AuthorizationHash, BrowserBindingHash, CSRFHash string
}
type Principal struct {
	TenantIssuer         grants.Scope
	SessionHash, Subject string
}
type BeginResult struct {
	Handle, CSRFToken string
	ExpiresAt         time.Time
}
type Consent struct {
	ClientName, ResourceName, RedirectURI string
	PermissionScopes                      []resources.Scope
	ExpiresAt                             time.Time
}
type Decision struct {
	Approve bool
	Proof   AccessProof
}
type DecisionResult struct{ Code, RedirectURI, State string }
type Service struct {
	store    Store
	clock    Clock
	material MaterialSource
}

func New(store Store, clock Clock, material MaterialSource) (*Service, error) {
	if store == nil || clock == nil || material == nil {
		return nil, ErrUnavailable
	}
	return &Service{store: store, clock: clock, material: material}, nil
}
func validMaterial(m Material) bool {
	return resources.ValidID(m.ID) && len(m.Secret) >= 43 && len(m.Secret) <= 128 && domain.ValidHandleHash(m.Hash) && m.Secret != m.Hash
}
func (s *Service) Begin(ctx context.Context, request domain.Request, browserBindingHash string) (BeginResult, error) {
	if !request.Valid() || !domain.ValidHandleHash(browserBindingHash) {
		return BeginResult{}, ErrInvalid
	}
	now := s.clock.Now()
	if now.IsZero() {
		return BeginResult{}, ErrUnavailable
	}
	var result BeginResult
	err := s.store.RunAuthorization(ctx, request.TenantIssuer, func(tx Transaction) error {
		registration, err := tx.Registration(ctx, request.ClientID, request.ResourceURI)
		if err != nil {
			return err
		}
		if !request.AllowedBy(registration) {
			return ErrInvalid
		}
		handle, err := s.material.NewAuthorizationMaterial(ctx)
		if err != nil || !validMaterial(handle) {
			return ErrUnavailable
		}
		csrf, err := s.material.NewAuthorizationMaterial(ctx)
		if err != nil || !validMaterial(csrf) || csrf.Hash == handle.Hash {
			return ErrUnavailable
		}
		workflow, err := domain.New(domain.Spec{ID: handle.ID, HandleHash: handle.Hash, BrowserBindingHash: browserBindingHash, CSRFHash: csrf.Hash, Request: request, PolicyVersion: registration.Policy.Version, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), Status: domain.Pending})
		if err != nil {
			return ErrInvalid
		}
		if err := tx.CreateAuthorization(ctx, workflow); err != nil {
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
func validProof(p AccessProof, mutation bool) bool {
	return p.TenantIssuer.Valid() && domain.ValidHandleHash(p.SessionHash) && domain.ValidHandleHash(p.AuthorizationHash) && domain.ValidHandleHash(p.BrowserBindingHash) && (!mutation || domain.ValidHandleHash(p.CSRFHash))
}
func (s *Service) principal(ctx context.Context, p AccessProof, mutation bool) (Principal, error) {
	if !validProof(p, mutation) {
		return Principal{}, ErrDenied
	}
	if !mutation {
		p.CSRFHash = ""
	}
	now := s.clock.Now()
	if now.IsZero() {
		return Principal{}, ErrDenied
	}
	actor, err := s.store.AuthorizeConsent(ctx, p, now)
	if err != nil || actor.TenantIssuer != p.TenantIssuer || actor.SessionHash != p.SessionHash || actor.Subject == "" {
		return Principal{}, ErrDenied
	}
	return actor, nil
}
func (s *Service) PrepareConsent(ctx context.Context, p AccessProof) (Consent, error) {
	p.CSRFHash = ""
	actor, err := s.principal(ctx, p, false)
	if err != nil {
		return Consent{}, err
	}
	var result Consent
	err = s.store.RunAuthorization(ctx, p.TenantIssuer, func(tx Transaction) error {
		workflow, current, err := s.consent(ctx, tx, p, actor)
		if err != nil {
			return err
		}
		spec := workflow.Snapshot()
		result = Consent{ClientName: current.Client.Name, ResourceName: current.Resource.Name, RedirectURI: spec.Request.RedirectURI, ExpiresAt: spec.ExpiresAt}
		for _, name := range spec.Request.PermissionScopes {
			for _, permission := range current.Resource.Scopes {
				if name == permission.Name {
					result.PermissionScopes = append(result.PermissionScopes, permission)
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return Consent{}, classified(err)
	}
	return result, nil
}
func (s *Service) Decide(ctx context.Context, d Decision) (DecisionResult, error) {
	actor, err := s.principal(ctx, d.Proof, true)
	if err != nil {
		return DecisionResult{}, err
	}
	var result DecisionResult
	err = s.store.RunAuthorization(ctx, d.Proof.TenantIssuer, func(tx Transaction) error {
		workflow, current, err := s.consent(ctx, tx, d.Proof, actor)
		if err != nil {
			return err
		}
		spec := workflow.Snapshot()
		var material Material
		if d.Approve {
			material, err = s.material.NewAuthorizationMaterial(ctx)
			if err != nil || !validMaterial(material) {
				return ErrUnavailable
			}
		}
		now := s.clock.Now()
		completed, revision, err := workflow.Decide(d.Approve, actor.Subject, material.ID, material.Hash, now, time.Duration(current.Policy.MaxGrantSeconds)*time.Second)
		if err != nil {
			return ErrDenied
		}
		if err := tx.CompleteAuthorization(ctx, completed, revision, now); err != nil {
			return err
		}
		result = DecisionResult{RedirectURI: spec.Request.RedirectURI, State: spec.Request.State}
		if d.Approve {
			result.Code = material.Secret
		}
		return nil
	})
	if err != nil {
		return DecisionResult{}, classified(err)
	}
	return result, nil
}
func classified(err error) error {
	if errors.Is(err, ErrDenied) {
		return ErrDenied
	}
	if errors.Is(err, ErrInvalid) {
		return ErrInvalid
	}
	return ErrUnavailable
}

// consent is the shared authorization, rehydration and session-binding path for
// presentation and approval. A transaction-local recheck precedes payload load.
func (s *Service) consent(ctx context.Context, tx Transaction, p AccessProof, actor Principal) (domain.Transaction, domain.Registration, error) {
	empty := domain.Transaction{}
	none := domain.Registration{}
	if err := tx.RecheckConsent(ctx, p, actor, s.clock.Now()); err != nil {
		return empty, none, err
	}
	workflow, err := tx.Authorization(ctx, p.AuthorizationHash)
	if err != nil {
		return empty, none, err
	}
	spec := workflow.Snapshot()
	now := s.clock.Now()
	if spec.Status != domain.Pending || spec.HandleHash != p.AuthorizationHash || spec.Request.TenantIssuer != p.TenantIssuer || spec.BrowserBindingHash != p.BrowserBindingHash || p.CSRFHash != "" && spec.CSRFHash != p.CSRFHash || now.Before(spec.CreatedAt) || !now.Before(spec.ExpiresAt) {
		return empty, none, ErrDenied
	}
	current, err := tx.Registration(ctx, spec.Request.ClientID, spec.Request.ResourceURI)
	if err != nil {
		return empty, none, err
	}
	if spec.PolicyVersion != current.Policy.Version || !spec.Request.AllowedBy(current) {
		return empty, none, ErrDenied
	}
	if spec.ConsentSessionHash == "" {
		bound, err := workflow.BindSession(actor.SessionHash, now)
		if err != nil {
			return empty, none, ErrDenied
		}
		if err := tx.BindConsentSession(ctx, bound); err != nil {
			return empty, none, err
		}
		workflow = bound
	} else if spec.ConsentSessionHash != actor.SessionHash {
		return empty, none, ErrDenied
	}
	if err := tx.RecheckConsent(ctx, p, actor, s.clock.Now()); err != nil {
		return empty, none, err
	}
	return workflow, current, nil
}
