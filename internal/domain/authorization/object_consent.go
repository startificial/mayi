package authorization

import (
	"slices"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

// ConsentObject is a minimal resource-owned display projection, never an
// object payload or a client-supplied title. Type/identifier remain visible.
type ConsentObject struct{ Type, Identifier, Name string }

type ObjectConsentSpec struct {
	AuthorizationHash, ClientID, Subject string
	PermissionVersion                    uint64
	Ceiling                              grants.ObjectCeiling
	Objects                              []ConsentObject
}

// ObjectConsentProjection validates correlation and display completeness only.
// The resource-owner port must establish current permission before constructing
// it; a structurally valid value is not an independent authorization decision.
type ObjectConsentProjection struct{ spec ObjectConsentSpec }

func NewObjectConsentProjection(s ObjectConsentSpec) (ObjectConsentProjection, error) {
	c := s.Ceiling.Snapshot()
	if !ValidHandleHash(s.AuthorizationHash) || !resources.ValidID(s.ClientID) || !grants.ValidUserSubject(s.Subject) || s.PermissionVersion == 0 || !s.Ceiling.BoundTo(c.Scope, c.Resource) || len(c.Details) == 0 || len(s.Objects) != len(c.Details) {
		return ObjectConsentProjection{}, ErrInvalid
	}
	type target struct{ typ, id string }
	expected := make(map[target]bool, len(c.Details))
	for _, detail := range c.Details {
		expected[target{detail.Type, detail.Identifier}] = true
	}
	for _, object := range s.Objects {
		key := target{object.Type, object.Identifier}
		if !expected[key] || !resources.ValidLabel(object.Name) {
			return ObjectConsentProjection{}, ErrInvalid
		}
		delete(expected, key)
	}
	s.Objects = slices.Clone(s.Objects)
	return ObjectConsentProjection{spec: s}, nil
}

func (p ObjectConsentProjection) Snapshot() ObjectConsentSpec {
	s := p.spec
	s.Objects = slices.Clone(s.Objects)
	return s
}

// Matches binds the resource decision to the exact pushed workflow and actor.
// It does not grant permission to approve or redeem a code by itself.
func (p ObjectConsentProjection) Matches(workflow Transaction, subject string) bool {
	w := workflow.Snapshot()
	_, err := NewObjectConsentProjection(p.spec)
	return err == nil && w.Status == Pending && w.PushedRequestHash != "" && p.spec.AuthorizationHash == w.HandleHash && p.spec.ClientID == w.Request.ClientID && p.spec.Subject == subject && p.spec.Ceiling.Equal(w.Request.ObjectCeiling)
}
