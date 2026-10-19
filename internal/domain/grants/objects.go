package grants

import (
	"errors"
	"slices"
	"strings"
)

const MaxObjectDetails = 32
const MaxObjectActions = 16
const MaxObjectIdentifierBytes = 256

var ErrInvalidObjectCeiling = errors.New("invalid object permission ceiling")
var ErrObjectExpansion = errors.New("requested objects exceed authorization ceiling")

// ObjectDetail describes this profile's complete type/object/action relationship.
// Its location is the enclosing ceiling's single resource, not an independent
// set that could be combined with other objects or actions. Type is an inert
// identifier; interpreting it requires a registered resource profile.
type ObjectDetail struct {
	Type, Identifier string
	Actions          []string
}

// ObjectCeilingSpec is an application value, not an RFC 9396 wire object. Scope
// must come from trusted issuer context. Empty Details explicitly permit nothing.
type ObjectCeilingSpec struct {
	Scope    Scope
	Resource string
	Details  []ObjectDetail
}

// ObjectCeiling is immutable. It limits delegated authority; it is never proof
// of current membership, grant status or the resource owner's current ACL.
type ObjectCeiling struct{ spec ObjectCeilingSpec }

// IsZero distinguishes missing object authority from a
// bound empty ceiling, which explicitly permits nothing. Neither grants access.
func (c ObjectCeiling) IsZero() bool {
	return c.spec.Scope == (Scope{}) && c.spec.Resource == "" && len(c.spec.Details) == 0
}

func (c ObjectCeiling) BoundTo(scope Scope, resource string) bool {
	return c.valid() && c.spec.Scope == scope && c.spec.Resource == resource
}

// Equal compares authority sets, preserving absence versus a bound denial.
func (c ObjectCeiling) Equal(other ObjectCeiling) bool {
	if c.IsZero() || other.IsZero() {
		return c.IsZero() && other.IsZero()
	}
	return c.IsSubsetOf(other) && other.IsSubsetOf(c)
}

func NewObjectCeiling(spec ObjectCeilingSpec) (ObjectCeiling, error) {
	if !spec.valid() {
		return ObjectCeiling{}, ErrInvalidObjectCeiling
	}
	spec.Details = cloneObjectDetails(spec.Details)
	return ObjectCeiling{spec: spec}, nil
}

func (c ObjectCeiling) Snapshot() ObjectCeilingSpec {
	s := c.spec
	s.Details = cloneObjectDetails(s.Details)
	return s
}

// ValidObjectDetails checks structural invariants only. Registered type/action
// semantics belong to domain/resources. A request additionally requires at
// least one entry; an empty stored/intersected ceiling means denial, never all.
func ValidObjectDetails(details []ObjectDetail) bool {
	if len(details) > MaxObjectDetails {
		return false
	}
	type object struct{ typ, identifier string }
	seen := make(map[object]bool, len(details))
	for _, d := range details {
		key := object{d.Type, d.Identifier}
		if !objectURI(d.Type) || !objectIdentifier(d.Identifier) || !ValidObjectActions(d.Actions) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func ValidObjectActions(actions []string) bool {
	if len(actions) == 0 || len(actions) > MaxObjectActions {
		return false
	}
	seen := make(map[string]bool, len(actions))
	for _, action := range actions {
		if len(action) == 0 || len(action) > 64 || seen[action] {
			return false
		}
		for _, c := range action {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-._:", c)) {
				return false
			}
		}
		seen[action] = true
	}
	return true
}

func objectIdentifier(s string) bool {
	if len(s) == 0 || len(s) > MaxObjectIdentifierBytes {
		return false
	}
	// Stable opaque ASCII references, with no wildcard syntax. In particular,
	// percent escapes, case and path separators are never decoded or normalized.
	for _, c := range s {
		if c <= 0x20 || c >= 0x7f || c == '*' || c == '?' {
			return false
		}
	}
	return true
}

// Structural check only; resources owns canonical URI registration validation.
func objectURI(s string) bool {
	if len(s) > 2048 || !strings.HasPrefix(s, "https://") || len(s) == len("https://") {
		return false
	}
	for _, c := range s {
		if c <= 0x20 || c >= 0x7f || strings.ContainsRune("*?#\\", c) {
			return false
		}
	}
	return true
}

func cloneObjectDetails(details []ObjectDetail) []ObjectDetail {
	out := slices.Clone(details)
	for i := range out {
		out[i].Actions = slices.Clone(out[i].Actions)
	}
	return out
}

func (c ObjectCeiling) valid() bool {
	return c.spec.valid()
}

func (s ObjectCeilingSpec) valid() bool {
	return s.Scope.Valid() && objectURI(s.Resource) && ValidObjectDetails(s.Details)
}

func (c ObjectCeiling) sameBinding(other ObjectCeiling) bool {
	return c.spec.Scope == other.spec.Scope && c.spec.Resource == other.spec.Resource
}

func containsObjectAction(details []ObjectDetail, typ, identifier, action string) bool {
	for _, d := range details {
		if d.Type == typ && d.Identifier == identifier && slices.Contains(d.Actions, action) {
			return true
		}
	}
	return false
}

// Permits checks only this ceiling, not authorization to read a protected object.
// The caller supplies the complete trusted binding and exact object reference.
func (c ObjectCeiling) Permits(scope Scope, resource, typ, identifier, action string) bool {
	return c.valid() && c.spec.Scope == scope && c.spec.Resource == resource && containsObjectAction(c.spec.Details, typ, identifier, action)
}

func (c ObjectCeiling) IsSubsetOf(other ObjectCeiling) bool {
	if !c.valid() || !other.valid() || !c.sameBinding(other) {
		return false
	}
	for _, d := range c.spec.Details {
		for _, action := range d.Actions {
			if !containsObjectAction(other.spec.Details, d.Type, d.Identifier, action) {
				return false
			}
		}
	}
	return true
}

// Narrow intersects this historical ceiling with current authority and every
// additional credential/policy ceiling. A nil request preserves that bounded
// intersection. An explicit empty request or any expansion is rejected. Missing
// or foreign ceilings are errors; an explicitly bound empty ceiling denies all.
// Cross-resource exchange requires a separately reviewed mapping, not this API.
func (c ObjectCeiling) Narrow(current ObjectCeiling, requested []ObjectDetail, additional ...ObjectCeiling) (ObjectCeiling, error) {
	if !c.valid() || !current.valid() || !c.sameBinding(current) {
		return ObjectCeiling{}, ErrObjectExpansion
	}
	ceilings := append([]ObjectCeiling{current}, additional...)
	available := c.Snapshot()
	for _, ceiling := range ceilings {
		if !ceiling.valid() || !c.sameBinding(ceiling) {
			return ObjectCeiling{}, ErrObjectExpansion
		}
		for i := range available.Details {
			d := &available.Details[i]
			d.Actions = slices.DeleteFunc(d.Actions, func(action string) bool {
				return !containsObjectAction(ceiling.spec.Details, d.Type, d.Identifier, action)
			})
		}
		available.Details = slices.DeleteFunc(available.Details, func(d ObjectDetail) bool { return len(d.Actions) == 0 })
	}
	bounded, err := NewObjectCeiling(available)
	if err != nil {
		return ObjectCeiling{}, ErrObjectExpansion
	}
	if requested == nil {
		return bounded, nil
	}
	if len(requested) == 0 {
		return ObjectCeiling{}, ErrObjectExpansion
	}
	wanted, err := NewObjectCeiling(ObjectCeilingSpec{Scope: c.spec.Scope, Resource: c.spec.Resource, Details: requested})
	if err != nil || !wanted.IsSubsetOf(bounded) {
		return ObjectCeiling{}, ErrObjectExpansion
	}
	return wanted, nil
}

// Union combines approvals for the same tenant, issuer and registered resource.
// Full tuples remain intact; cross-resource and oversized unions fail closed.
func (c ObjectCeiling) Union(other ObjectCeiling) (ObjectCeiling, error) {
	a, b := c.Snapshot(), other.Snapshot()
	if c.IsZero() || other.IsZero() || a.Scope != b.Scope || a.Resource != b.Resource {
		return ObjectCeiling{}, ErrInvalidObjectCeiling
	}
	for _, detail := range b.Details {
		found := false
		for i := range a.Details {
			if a.Details[i].Type == detail.Type && a.Details[i].Identifier == detail.Identifier {
				for _, action := range detail.Actions {
					if !slices.Contains(a.Details[i].Actions, action) {
						a.Details[i].Actions = append(a.Details[i].Actions, action)
					}
				}
				found = true
				break
			}
		}
		if !found {
			a.Details = append(a.Details, detail)
		}
	}
	return NewObjectCeiling(a)
}
