package resources

import (
	"errors"
	"slices"
	"strings"

	"github.com/startificial/mayi/internal/domain/grants"
)

// DocumentV1 names Mayi's exact object/action semantics, not a universal RFC type.
// A resource owner assigns a distinct versioned Type URI under its own control.
const DocumentV1 = "document-v1"

var ErrInvalidDocumentProfile = errors.New("invalid document authorization profile")
var ErrInvalidDocumentRequest = errors.New("invalid document authorization details")

type DocumentAction struct{ Name, Description string }
type DocumentProfileSpec struct {
	Scope                     grants.Scope
	Resource, Type, Semantics string
	Actions                   []DocumentAction
}

// DocumentProfile is a trusted, immutable registration snapshot. Neither its
// URI identifiers nor client-supplied identifiers trigger schema/document I/O.
// Resource integrations supply current permission and safe display projections
// separately; passing schema validation does not authorize document access.
type DocumentProfile struct{ spec DocumentProfileSpec }

func NewDocumentProfile(s DocumentProfileSpec) (DocumentProfile, error) {
	if !s.Scope.Valid() || !ValidURI(s.Resource) || !ValidURI(s.Type) || strings.ContainsAny(s.Resource+s.Type, "*") || s.Semantics != DocumentV1 {
		return DocumentProfile{}, ErrInvalidDocumentProfile
	}
	names := make([]string, 0, len(s.Actions))
	for _, action := range s.Actions {
		if !ValidLabel(action.Description) {
			return DocumentProfile{}, ErrInvalidDocumentProfile
		}
		names = append(names, action.Name)
	}
	if !grants.ValidObjectActions(names) {
		return DocumentProfile{}, ErrInvalidDocumentProfile
	}
	s.Actions = slices.Clone(s.Actions)
	return DocumentProfile{spec: s}, nil
}

func (p DocumentProfile) Snapshot() DocumentProfileSpec {
	s := p.spec
	s.Actions = slices.Clone(s.Actions)
	return s
}

// ValidateRequest rejects absent details instead of falling back to broad
// scopes. Scope permissions, when used, are a separate additional ceiling.
// Every caller must validate against its current trusted registration snapshot.
func (p DocumentProfile) ValidateRequest(scope grants.Scope, resource string, details []grants.ObjectDetail) (grants.ObjectCeiling, error) {
	if _, err := NewDocumentProfile(p.spec); err != nil || scope != p.spec.Scope || resource != p.spec.Resource || len(details) == 0 {
		return grants.ObjectCeiling{}, ErrInvalidDocumentRequest
	}
	ceiling, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: scope, Resource: resource, Details: details})
	if err != nil {
		return grants.ObjectCeiling{}, ErrInvalidDocumentRequest
	}
	for _, detail := range details {
		if detail.Type != p.spec.Type {
			return grants.ObjectCeiling{}, ErrInvalidDocumentRequest
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
				return grants.ObjectCeiling{}, ErrInvalidDocumentRequest
			}
		}
	}
	return ceiling, nil
}
