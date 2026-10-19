package resources

import (
	"errors"
	"slices"
	"strings"

	"github.com/startificial/mayi/internal/domain/grants"
)

// ObjectActionsV1 names Mayi's exact object/action semantics, not a universal RFC type.
// A resource owner assigns a distinct versioned Type URI under its own control.
const ObjectActionsV1 = "object-actions-v1"

var ErrInvalidObjectProfile = errors.New("invalid object authorization profile")
var ErrInvalidObjectRequest = errors.New("invalid object authorization details")

type ObjectAction struct{ Name, Description string }
type ObjectProfileSpec struct {
	Scope                     grants.Scope
	Resource, Type, Semantics string
	Actions                   []ObjectAction
}

// ObjectProfile is a trusted, immutable registration snapshot. Neither its
// URI identifiers nor client-supplied identifiers trigger schema/object I/O.
// Resource integrations supply current permission and safe display projections
// separately; passing schema validation does not authorize object access.
type ObjectProfile struct{ spec ObjectProfileSpec }

func NewObjectProfile(s ObjectProfileSpec) (ObjectProfile, error) {
	if !s.Scope.Valid() || !ValidURI(s.Resource) || strings.Contains(s.Resource, "*") || !ValidObjectTypeURI(s.Type) || s.Semantics != ObjectActionsV1 {
		return ObjectProfile{}, ErrInvalidObjectProfile
	}
	names := make([]string, 0, len(s.Actions))
	for _, action := range s.Actions {
		if !ValidLabel(action.Description) {
			return ObjectProfile{}, ErrInvalidObjectProfile
		}
		names = append(names, action.Name)
	}
	if !grants.ValidObjectActions(names) {
		return ObjectProfile{}, ErrInvalidObjectProfile
	}
	s.Actions = slices.Clone(s.Actions)
	return ObjectProfile{spec: s}, nil
}

// ValidObjectTypeURI validates an inert, exact type identifier. A type's
// interpretation is immutable; different semantics require a new identifier.
func ValidObjectTypeURI(uri string) bool {
	return ValidURI(uri) && !strings.Contains(uri, "*")
}

func (p ObjectProfile) Snapshot() ObjectProfileSpec {
	s := p.spec
	s.Actions = slices.Clone(s.Actions)
	return s
}

// ValidateRequest rejects absent details instead of falling back to broad
// scopes. Scope permissions, when used, are a separate additional ceiling.
// Every caller must validate against its current trusted registration snapshot.
func (p ObjectProfile) ValidateRequest(scope grants.Scope, resource string, details []grants.ObjectDetail) (grants.ObjectCeiling, error) {
	if _, err := NewObjectProfile(p.spec); err != nil || scope != p.spec.Scope || resource != p.spec.Resource || len(details) == 0 {
		return grants.ObjectCeiling{}, ErrInvalidObjectRequest
	}
	ceiling, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: scope, Resource: resource, Details: details})
	if err != nil {
		return grants.ObjectCeiling{}, ErrInvalidObjectRequest
	}
	for _, detail := range details {
		if detail.Type != p.spec.Type {
			return grants.ObjectCeiling{}, ErrInvalidObjectRequest
		}
		for _, requested := range detail.Actions {
			found := false
			for _, action := range p.spec.Actions {
				if action.Name == requested {
					found = true
					break
				}
			}
			if !found {
				return grants.ObjectCeiling{}, ErrInvalidObjectRequest
			}
		}
	}
	return ceiling, nil
}
