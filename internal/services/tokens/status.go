package tokens

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/resources"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"net/url"
	"slices"
	"strings"
)

type StatusService struct {
	store     StatusStore
	hasher    SecretHasher
	material  MaterialSource
	proofs    ResourceProofs
	admission UsageAdmission
}

func NewStatus(store StatusStore, h SecretHasher, m MaterialSource, proofs ResourceProofs, admission UsageAdmission) (*StatusService, error) {
	if admission == nil || store == nil || h == nil || m == nil || proofs == nil {
		return nil, ErrUnavailable
	}
	return &StatusService{store, h, m, proofs, admission}, nil
}

// Introspect authenticates and authorizes the resource reference before the
// credential lookup. Zero Claims is the standard inactive result, not an error.
func (s *StatusService) Introspect(ctx context.Context, caller StatusCaller, raw, resource string) (Result, error) {
	if !caller.Scope.Valid() || caller.ClientID == "" || !caller.Introspection || !resources.ValidURI(resource) || !slices.Contains(caller.Resources, resource) {
		return Result{}, ErrInvalidCredential
	}
	if err := s.admission.Check(ctx, caller.Scope, "introspection", "client", caller.ClientID); err != nil {
		return Result{}, err
	}
	if raw == "" || len(raw) > 65536 {
		return Result{}, s.store.RecordInactive(ctx, caller, resource)
	}
	hash, err := s.hasher.Digest(caller.Scope, "access_token", raw)
	if err != nil {
		hash = s.material.DigestAccessToken(raw)
	}
	result, err := s.store.AccessStatus(ctx, caller, hash, resource)
	if err != nil {
		return Result{}, err
	}
	if result.Claims.ID == "" {
		if err := s.store.RecordInactive(ctx, caller, resource); err != nil {
			return Result{}, err
		}
	}
	if result.Claims.ID != "" {
		if err := s.admission.Check(ctx, caller.Scope, "introspection", "user", result.Claims.Subject); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}
func (s *StatusService) Revoke(ctx context.Context, caller StatusCaller, raw, hint string) error {
	if !caller.Scope.Valid() || caller.ClientID == "" {
		return ErrInvalidCredential
	}
	if raw == "" || len(raw) > 65536 {
		return nil
	}
	// Both searches are owner-scoped and deliberately reveal no credential state.
	{ // A hint is advisory; a wrong hint cannot prevent revocation.
		if hash, err := s.hasher.Digest(caller.Scope, RefreshToken, raw); err == nil {
			if err := s.store.RevokeCredential(ctx, caller, hash, RefreshToken); err != nil {
				return err
			}
		}
	}
	hash, err := s.hasher.Digest(caller.Scope, "access_token", raw)
	if err != nil {
		hash = s.material.DigestAccessToken(raw)
	}
	return s.store.RevokeCredential(ctx, caller, hash, "access_token")
}

// Introspection is the resource's authenticated online decision request. The URL
// is never fetched; the proof may address only this registered audience's path.
type Introspection struct{ Token, Resource, Proof, Method, URL string }

func (s *StatusService) Inspect(ctx context.Context, caller StatusCaller, q Introspection) (Result, bool, error) {
	if q.Resource == "" && len(caller.Resources) == 1 {
		q.Resource = caller.Resources[0]
	}
	result, err := s.Introspect(ctx, caller, q.Token, q.Resource)
	if err != nil || result.Claims.ID == "" || q.Proof == "" {
		return result, false, err
	}
	targetURI, ok := domain.ProofTarget(q.URL, false)
	audienceURI, audienceOK := domain.ProofTarget(q.Resource, false)
	target, _ := url.Parse(targetURI)
	audience, _ := url.Parse(audienceURI)
	if !ok || !audienceOK || target.Scheme != audience.Scheme || target.Host != audience.Host || (target.Path != audience.Path && !strings.HasPrefix(target.Path, strings.TrimSuffix(audience.Path, "/")+"/")) {
		return Result{}, false, s.store.RecordInactive(ctx, caller, q.Resource)
	}
	if result.Claims.BindingThumbprint == "" {
		return Result{}, false, ErrInvalidProof
	}
	thumb, err := s.proofs.Verify(ctx, caller.Scope, ProofRequest{JWT: q.Proof, Method: q.Method, URL: q.URL, AccessToken: q.Token, ExpectedThumbprint: result.Claims.BindingThumbprint})
	if err != nil {
		var challenge *NonceChallenge
		if errors.As(err, &challenge) || errors.Is(err, ErrUnavailable) {
			return Result{}, false, err
		}
		if e := s.store.RecordInactive(ctx, caller, q.Resource); e != nil {
			return Result{}, false, ErrUnavailable
		}
		return Result{}, false, ErrInvalidProof
	}
	if thumb == "" || thumb != result.Claims.BindingThumbprint {
		return Result{}, false, ErrInvalidProof
	}
	return result, true, nil
}
