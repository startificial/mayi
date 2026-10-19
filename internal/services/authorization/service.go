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
	ClientID, ResourceURI                 string
	PermissionScopes                      []resources.Scope
	ExpiresAt                             time.Time
	Objects                               []ConsentObject
	PermissionVersion                     uint64
	DecisionAvailable                     bool
}
type ConsentObject struct {
	Type, Identifier, Name string
	Actions                []resources.ObjectAction
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
	objects  ObjectConsentAuthority
}

// A nil object authority keeps typed consent closed. Composition must explicitly
// select a reviewed resource-owner integration before enabling object display.
func New(store Store, clock Clock, material MaterialSource, objects ObjectConsentAuthority) (*Service, error) {
	if store == nil || clock == nil || material == nil {
		return nil, ErrUnavailable
	}
	return &Service{store: store, clock: clock, material: material, objects: objects}, nil
}
func validMaterial(m Material) bool {
	return resources.ValidID(m.ID) && len(m.Secret) >= 43 && len(m.Secret) <= 128 && domain.ValidHandleHash(m.Hash) && m.Secret != m.Hash
}
func (s *Service) Begin(ctx context.Context, request domain.Request, browserBindingHash string) (BeginResult, error) {
	if !request.Valid() || !request.ObjectCeiling.IsZero() || !domain.ValidHandleHash(browserBindingHash) {
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
	var candidate domain.Transaction
	err = s.store.RunAuthorization(ctx, p.TenantIssuer, func(tx Transaction) error {
		workflow, current, err := s.loadConsent(ctx, tx, p, actor, s.objects != nil)
		if err != nil {
			return err
		}
		if !workflow.Snapshot().Request.ObjectCeiling.IsZero() {
			candidate = workflow
			return nil
		}
		workflow, err = s.bindConsent(ctx, tx, p, actor, workflow)
		if err != nil {
			return err
		}
		result = consentView(workflow, current)
		return nil
	})
	if err != nil {
		return Consent{}, classified(err)
	}
	if candidate.Snapshot().HandleHash != "" {
		return s.prepareObjectConsent(ctx, p, actor, candidate)
	}
	return result, nil
}
func (s *Service) Decide(ctx context.Context, d Decision) (DecisionResult, error) {
	actor, err := s.principal(ctx, d.Proof, true)
	if err != nil {
		return DecisionResult{}, err
	}
	var result DecisionResult
	var candidate domain.Transaction
	err = s.store.RunAuthorization(ctx, d.Proof.TenantIssuer, func(tx Transaction) error {
		workflow, current, err := s.loadConsent(ctx, tx, d.Proof, actor, s.objects != nil)
		if err != nil {
			return err
		}
		if d.Approve && !workflow.Snapshot().Request.ObjectCeiling.IsZero() {
			candidate = workflow
			return nil
		}
		workflow, err = s.bindConsent(ctx, tx, d.Proof, actor, workflow)
		if err != nil {
			return err
		}
		result, err = s.completeDecision(ctx, tx, workflow, current, actor, d.Approve, domain.ObjectConsentProjection{}, domain.ObjectConsentProjection{})
		return err
	})
	if err != nil {
		return DecisionResult{}, classified(err)
	}
	if candidate.Snapshot().HandleHash != "" {
		return s.approveObjectConsent(ctx, d.Proof, actor, candidate)
	}
	return result, nil
}

func (s *Service) completeDecision(ctx context.Context, tx Transaction, workflow domain.Transaction, current domain.Registration, actor Principal, approve bool, presented, fresh domain.ObjectConsentProjection) (DecisionResult, error) {
	var material Material
	var err error
	if approve {
		material, err = s.material.NewAuthorizationMaterial(ctx)
		if err != nil || !validMaterial(material) {
			return DecisionResult{}, ErrUnavailable
		}
	}
	now := s.clock.Now()
	lifetime := time.Duration(current.Policy.MaxGrantSeconds) * time.Second
	var completed domain.Transaction
	var revision grants.Revision
	if approve && !workflow.Snapshot().Request.ObjectCeiling.IsZero() {
		completed, revision, err = workflow.ApproveObjects(presented, fresh, actor.Subject, material.ID, material.Hash, now, lifetime)
	} else {
		completed, revision, err = workflow.Decide(approve, actor.Subject, material.ID, material.Hash, now, lifetime)
	}
	if err != nil {
		return DecisionResult{}, ErrDenied
	}
	if err := tx.CompleteAuthorization(ctx, completed, revision, now); err != nil {
		return DecisionResult{}, err
	}
	r := workflow.Snapshot().Request
	result := DecisionResult{RedirectURI: r.RedirectURI, State: r.State}
	if approve {
		result.Code = material.Secret
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

// loadConsent shares authorization and rehydration for presentation/approval.
// A transaction-local recheck precedes payload load; it never binds a session.
func (s *Service) loadConsent(ctx context.Context, tx Transaction, p AccessProof, actor Principal, allowObjects bool) (domain.Transaction, domain.Registration, error) {
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
	allowed := spec.Request.AllowedBy(current)
	if allowObjects && spec.PushedRequestHash != "" && !spec.Request.ObjectCeiling.IsZero() {
		allowed = spec.Request.MatchesObjectRegistration(current)
	}
	if spec.PolicyVersion != current.Policy.Version || !allowed || spec.ConsentSessionHash != "" && spec.ConsentSessionHash != actor.SessionHash {
		return empty, none, ErrDenied
	}
	return workflow, current, nil
}

func (s *Service) bindConsent(ctx context.Context, tx Transaction, p AccessProof, actor Principal, workflow domain.Transaction) (domain.Transaction, error) {
	spec := workflow.Snapshot()
	now := s.clock.Now()
	if spec.ConsentSessionHash == "" {
		bound, err := workflow.BindSession(actor.SessionHash, now)
		if err != nil {
			return domain.Transaction{}, ErrDenied
		}
		if err := tx.BindConsentSession(ctx, bound); err != nil {
			return domain.Transaction{}, err
		}
		workflow = bound
	} else if spec.ConsentSessionHash != actor.SessionHash {
		return domain.Transaction{}, ErrDenied
	}
	if err := tx.RecheckConsent(ctx, p, actor, s.clock.Now()); err != nil {
		return domain.Transaction{}, err
	}
	return workflow, nil
}
