package authorization

import (
	"slices"
	"time"

	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

// Permission versions use the positive signed-64-bit revision space.
const MaxPermissionVersion uint64 = 1<<63 - 1

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
	if !ValidHandleHash(s.AuthorizationHash) || !clients.ValidClientID(s.ClientID) || !grants.ValidUserSubject(s.Subject) || s.PermissionVersion == 0 || s.PermissionVersion > MaxPermissionVersion || !s.Ceiling.BoundTo(c.Scope, c.Resource) || len(c.Details) == 0 || len(s.Objects) != len(c.Details) {
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

// Equal preserves the exact displayed labels and permission revision. Order of
// provider entries is irrelevant; the workflow determines presentation order.
func (p ObjectConsentProjection) Equal(other ObjectConsentProjection) bool {
	if _, err := NewObjectConsentProjection(p.spec); err != nil {
		return false
	}
	if _, err := NewObjectConsentProjection(other.spec); err != nil {
		return false
	}
	a, b := p.spec, other.spec
	if a.AuthorizationHash != b.AuthorizationHash || a.ClientID != b.ClientID || a.Subject != b.Subject || a.PermissionVersion != b.PermissionVersion || !a.Ceiling.Equal(b.Ceiling) || len(a.Objects) != len(b.Objects) {
		return false
	}
	for _, object := range a.Objects {
		if !slices.Contains(b.Objects, object) {
			return false
		}
	}
	return true
}

// ApproveObjects requires immutable presentation evidence and a matching fresh
// guarded decision. Resource guard lifetime is the consuming service's duty.
func (t Transaction) ApproveObjects(presented, current ObjectConsentProjection, subject, grantID, codeHash string, now time.Time, lifetime time.Duration) (Transaction, grants.Revision, error) {
	return t.ApproveIncrementalObjects(presented, current, subject, grantID, codeHash, now, lifetime, nil)
}

// ApproveIncrementalObjects carries the current root snapshot only while making
// new consent. Old credentials continue to reference their immutable revision.
func (t Transaction) ApproveIncrementalObjects(presented, current ObjectConsentProjection, subject, grantID, codeHash string, now time.Time, lifetime time.Duration, previous *grants.Revision) (Transaction, grants.Revision, error) {
	if !presented.Matches(t, subject) || !current.Matches(t, subject) || !presented.Equal(current) {
		return Transaction{}, grants.Revision{}, ErrInvalid
	}
	return t.decide(true, subject, grantID, codeHash, now, lifetime, previous)
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
