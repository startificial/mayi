// Package grants defines immutable authorization ceilings without persistence or I/O.
package grants

import (
	"errors"
	"slices"
	"strings"
	"time"
)

var ErrInvalidRevision = errors.New("invalid grant revision")
var ErrScopeExpansion = errors.New("requested scopes exceed authorization ceiling")

// Scope is established from trusted issuer configuration, never a request tenant ID.
type Scope struct{ TenantID, Issuer string }

func (s Scope) Valid() bool {
	return validID(s.TenantID) && s.Issuer != "" && len(s.Issuer) <= 2048 && !strings.ContainsAny(s.Issuer, "\r\n\x00")
}

type RevisionSpec struct {
	Scope                                      Scope
	GrantID                                    string
	Number                                     uint64
	ClientID, Subject, PrincipalType, Resource string
	Scopes                                     []string
	ObjectCeiling                              ObjectCeiling
	ExpiresAt                                  time.Time
}

// Revision takes a snapshot: later consent cannot enlarge an older credential.
type Revision struct{ spec RevisionSpec }

// ValidReferences validates the grant's identity tuple independently of a
// permission ceiling or lifetime. Reference projections need no synthetic grant.
func (spec RevisionSpec) ValidReferences() bool {
	if !spec.Scope.Valid() || !validID(spec.GrantID) || spec.Number == 0 || !validID(spec.ClientID) || !validID(spec.Subject) || spec.Resource == "" || len(spec.Resource) > 2048 {
		return false
	}
	switch spec.PrincipalType {
	case "user":
		if !ValidUserSubject(spec.Subject) {
			return false
		}
	case "machine":
		if spec.Subject != spec.ClientID || !strings.HasPrefix(spec.ClientID, "client:") {
			return false
		}
	default:
		return false
	}
	return true
}

// ValidUserSubject is the existing local user-reference grammar shared by
// grant references and consent correlation, not an upstream identity assertion.
func ValidUserSubject(subject string) bool {
	return validID(subject) && strings.HasPrefix(subject, "user:")
}

func NewRevision(spec RevisionSpec) (Revision, error) {
	if !spec.ValidReferences() || spec.ExpiresAt.IsZero() {
		return Revision{}, ErrInvalidRevision
	}
	if !ValidScopes(spec.Scopes) {
		return Revision{}, ErrInvalidRevision
	}
	if !spec.ObjectCeiling.BoundTo(spec.Scope, spec.Resource) || len(spec.ObjectCeiling.Snapshot().Details) == 0 {
		return Revision{}, ErrInvalidRevision
	}
	spec.Scopes = slices.Clone(spec.Scopes)
	return Revision{spec: spec}, nil
}

func (r Revision) Snapshot() RevisionSpec {
	spec := r.spec
	spec.Scopes = slices.Clone(spec.Scopes)
	return spec
}

// Narrow intersects current authorization with the historical revision. Empty
// requested scopes mean the available intersection; an explicit expansion fails.
func (r Revision) Narrow(current, requested []string, additional ...[]string) ([]string, error) {
	if !ValidScopes(current) || !ValidScopes(requested) {
		return nil, ErrScopeExpansion
	}
	available := make([]string, 0, len(r.spec.Scopes))
	for _, scope := range r.spec.Scopes {
		if slices.Contains(current, scope) {
			available = append(available, scope)
		}
	}
	for _, ceiling := range additional {
		if !ValidScopes(ceiling) {
			return nil, ErrScopeExpansion
		}
		available = slices.DeleteFunc(available, func(scope string) bool { return !slices.Contains(ceiling, scope) })
	}
	if len(requested) == 0 {
		return available, nil
	}
	for _, scope := range requested {
		if !slices.Contains(available, scope) {
			return nil, ErrScopeExpansion
		}
	}
	return slices.Clone(requested), nil
}

func ValidScopes(scopes []string) bool {
	seen := make(map[string]bool, len(scopes))
	if len(scopes) > 128 {
		return false
	}
	for _, scope := range scopes {
		if len(scope) == 0 || len(scope) > 256 || seen[scope] {
			return false
		}
		for _, c := range []byte(scope) {
			if !(c == 0x21 || c >= 0x23 && c <= 0x5b || c >= 0x5d && c <= 0x7e) {
				return false
			}
		}
		seen[scope] = true
	}
	return true
}

func validID(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if c <= 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// Extend records a new consent revision. Existing revisions and credential
// ceilings remain unchanged; new credentials still carry their exact request.
func (r Revision) Extend(request RevisionSpec) (Revision, error) {
	old := r.Snapshot()
	if _, err := NewRevision(old); err != nil {
		return Revision{}, ErrInvalidRevision
	}
	if old.Scope != request.Scope || old.ClientID != request.ClientID || old.Subject != request.Subject || old.PrincipalType != "user" || request.PrincipalType != "user" || old.Resource != request.Resource || old.Number >= 1<<63-1 {
		return Revision{}, ErrInvalidRevision
	}
	objects, err := old.ObjectCeiling.Union(request.ObjectCeiling)
	if err != nil {
		return Revision{}, ErrInvalidRevision
	}
	scopes := slices.Clone(old.Scopes)
	for _, name := range request.Scopes {
		if !slices.Contains(scopes, name) {
			scopes = append(scopes, name)
		}
	}
	request.GrantID = old.GrantID
	request.Number = old.Number + 1
	request.Scopes = scopes
	request.ObjectCeiling = objects
	return NewRevision(request)
}
