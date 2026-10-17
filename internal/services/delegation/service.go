// Package delegation contains the disabled P0 recipient-exchange planning hook.
// It cannot issue a credential. P4 must add atomic lineage persistence and the
// authenticated gateway receipt contract before exposing an exchange endpoint.
package delegation

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"slices"
	"time"
)

var ErrDenied = errors.New("exchange denied")

type Command struct {
	Scope                                                    grants.Scope
	CallerClientID, SubjectID, Resource, ReceivingThumbprint string
	Scopes                                                   []string
}
type Edge struct {
	Scope                                             grants.Scope
	RecipientClientID, SourceResource, TargetResource string
	Scopes                                            []string
	Lifetime                                          time.Duration
}
type Subject struct {
	Claims domain.AccessClaims
	Active bool
	Actors []string
}
type Plan struct {
	Scope                                  grants.Scope
	ParentID, GrantID                      string
	Revision                               uint64
	Subject, Resource, ReceivingThumbprint string
	Scopes, Actors                         []string
	ExpiresAt                              time.Time
}
type Service struct {
	policy   Authorizer
	subjects SubjectReader
	clock    Clock
}

func New(p Authorizer, r SubjectReader, c Clock) (*Service, error) {
	if p == nil || r == nil || c == nil {
		return nil, ErrDenied
	}
	return &Service{policy: p, subjects: r, clock: c}, nil
}
func (s *Service) PlanExchange(ctx context.Context, c Command) (Plan, error) {
	if !c.Scope.Valid() || c.CallerClientID == "" || c.SubjectID == "" || c.Resource == "" || c.ReceivingThumbprint == "" || len(c.Scopes) == 0 || !grants.ValidScopes(c.Scopes) {
		return Plan{}, ErrDenied
	}
	edge, err := s.policy.AuthorizeExchange(ctx, c)
	if err != nil {
		return Plan{}, ErrDenied
	}
	if edge.Scope != c.Scope || edge.RecipientClientID != c.CallerClientID || edge.TargetResource != c.Resource || edge.SourceResource == edge.TargetResource || edge.Lifetime <= 0 || edge.Lifetime > 15*time.Minute {
		return Plan{}, ErrDenied
	}
	subject, err := s.subjects.ReadSubject(ctx, c.Scope, c.SubjectID)
	if err != nil {
		return Plan{}, ErrDenied
	}
	parent := subject.Claims
	now := s.clock.Now()
	// P0 proves one recipient hop with a same-name scope attenuation map. All
	// further hops, cross-tenant exchange and impersonation remain unsupported.
	if !subject.Active || len(subject.Actors) != 0 || parent.Scope != c.Scope || parent.Resource != edge.SourceResource || parent.ID != c.SubjectID || parent.GrantID == "" || parent.Revision == 0 || parent.PrincipalType != "user" || !parent.ExpiresAt.After(now) || now.IsZero() {
		return Plan{}, ErrDenied
	}
	for _, scope := range c.Scopes {
		if !slices.Contains(parent.Scopes, scope) || !slices.Contains(edge.Scopes, scope) {
			return Plan{}, ErrDenied
		}
	}
	expires := now.Add(edge.Lifetime)
	if parent.ExpiresAt.Before(expires) {
		expires = parent.ExpiresAt
	}
	return Plan{Scope: c.Scope, ParentID: parent.ID, GrantID: parent.GrantID, Revision: parent.Revision, Subject: parent.Subject, Resource: c.Resource, ReceivingThumbprint: c.ReceivingThumbprint, Scopes: slices.Clone(c.Scopes), Actors: []string{c.CallerClientID}, ExpiresAt: expires}, nil
}
