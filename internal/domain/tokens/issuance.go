// Package tokens defines token-purpose and attenuation invariants. It does not encode JWTs.
package tokens

import (
	"errors"
	"slices"
	"time"

	"github.com/startificial/mayi/internal/domain/grants"
)

var ErrInvalidIssuance = errors.New("invalid token issuance")

// AccessClaims are application values; protocol serialization belongs in adapters.
type AccessClaims struct {
	ID                                         string
	Scope                                      grants.Scope
	GrantID                                    string
	Revision                                   uint64
	Subject, PrincipalType, ClientID, Resource string
	Scopes                                     []string
	ObjectCeiling                              grants.ObjectCeiling
	BindingThumbprint                          string
	IssuedAt, ExpiresAt                        time.Time
}

func Derive(revision grants.Revision, current, requested []string, id, binding string, now time.Time, lifetime time.Duration, deadlines ...time.Time) (AccessClaims, error) {
	spec := revision.Snapshot()
	// Scope-only callers cannot discard object authority. Object-aware callers
	// must use DeriveObjects with an explicitly attenuated complete ceiling.
	if !spec.ObjectCeiling.IsZero() {
		return AccessClaims{}, ErrInvalidIssuance
	}
	return derive(revision, current, requested, grants.ObjectCeiling{}, id, binding, now, lifetime, deadlines...)
}

// DeriveObjects accepts only the already attenuated complete object tuples.
// The application must also enforce credential/current-grant ceilings and policy.
func DeriveObjects(revision grants.Revision, current, requested []string, objects grants.ObjectCeiling, id, binding string, now time.Time, lifetime time.Duration, deadlines ...time.Time) (AccessClaims, error) {
	s := revision.Snapshot()
	if s.ObjectCeiling.IsZero() || !objects.BoundTo(s.Scope, s.Resource) || len(objects.Snapshot().Details) == 0 || !objects.IsSubsetOf(s.ObjectCeiling) {
		return AccessClaims{}, ErrInvalidIssuance
	}
	return derive(revision, current, requested, objects, id, binding, now, lifetime, deadlines...)
}

func derive(revision grants.Revision, current, requested []string, objects grants.ObjectCeiling, id, binding string, now time.Time, lifetime time.Duration, deadlines ...time.Time) (AccessClaims, error) {
	spec := revision.Snapshot()
	// Revalidate zero values and data reconstituted by an adapter.
	if _, err := grants.NewRevision(spec); err != nil || id == "" || len(id) > 256 || now.IsZero() || lifetime <= 0 || lifetime > 15*time.Minute {
		return AccessClaims{}, ErrInvalidIssuance
	}
	scopes, err := revision.Narrow(current, requested)
	if err != nil || len(scopes) == 0 {
		return AccessClaims{}, ErrInvalidIssuance
	}
	expiry := now.Add(lifetime)
	for _, deadline := range append([]time.Time{spec.ExpiresAt}, deadlines...) {
		if deadline.IsZero() {
			return AccessClaims{}, ErrInvalidIssuance
		}
		if deadline.Before(expiry) {
			expiry = deadline
		}
	}
	if !expiry.After(now) {
		return AccessClaims{}, ErrInvalidIssuance
	}
	return AccessClaims{ID: id, Scope: spec.Scope, GrantID: spec.GrantID, Revision: spec.Number, Subject: spec.Subject, PrincipalType: spec.PrincipalType, ClientID: spec.ClientID, Resource: spec.Resource, Scopes: slices.Clone(scopes), ObjectCeiling: objects, BindingThumbprint: binding, IssuedAt: now, ExpiresAt: expiry}, nil
}
