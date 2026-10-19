package grants

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func objectSpec() ObjectCeilingSpec {
	return ObjectCeilingSpec{Scope: revisionSpec().Scope, Resource: "https://api.example/a", Details: []ObjectDetail{
		{Type: "https://api.example/types/document/v1", Identifier: "123", Actions: []string{"read"}},
		{Type: "https://api.example/types/document/v1", Identifier: "124", Actions: []string{"write"}},
	}}
}
func objectCeiling(t *testing.T, s ObjectCeilingSpec) ObjectCeiling {
	t.Helper()
	c, err := NewObjectCeiling(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestObjectCeilingKeepsCompleteTuplesAndTrustedBinding(t *testing.T) {
	s := objectSpec()
	c := objectCeiling(t, s)
	for _, tc := range []struct {
		identifier, action string
		want               bool
	}{{"123", "read", true}, {"124", "write", true}, {"124", "read", false}, {"123", "write", false}, {"1234", "read", false}, {"123/child", "read", false}, {"%31%32%33", "read", false}} {
		if got := c.Permits(s.Scope, s.Resource, s.Details[0].Type, tc.identifier, tc.action); got != tc.want {
			t.Fatalf("%s/%s: %v", tc.identifier, tc.action, got)
		}
	}
	for _, mutate := range []func(*ObjectCeilingSpec){
		func(s *ObjectCeilingSpec) { s.Scope.TenantID = "tenant-b" },
		func(s *ObjectCeilingSpec) { s.Scope.Issuer += "/other" },
		func(s *ObjectCeilingSpec) { s.Resource += "/other" },
		func(s *ObjectCeilingSpec) { s.Details[0].Type += "/v2" },
	} {
		foreign := c.Snapshot()
		mutate(&foreign)
		other := objectCeiling(t, foreign)
		if c.Permits(foreign.Scope, foreign.Resource, foreign.Details[0].Type, "123", "read") || c.IsSubsetOf(other) || other.IsSubsetOf(c) {
			t.Fatal("foreign binding or type matched")
		}
		got, err := c.Narrow(other, nil)
		if foreign.Scope != s.Scope || foreign.Resource != s.Resource {
			if !errors.Is(err, ErrObjectExpansion) {
				t.Fatalf("foreign narrowing succeeded: %v", err)
			}
		} else if err != nil || got.Permits(s.Scope, s.Resource, s.Details[0].Type, "123", "read") || !got.IsSubsetOf(c) {
			t.Fatalf("a new type version resurrected the old permission: %v", err)
		}
	}
}

func TestObjectCeilingSnapshotsAreDeeplyImmutable(t *testing.T) {
	s := objectSpec()
	c := objectCeiling(t, s)
	s.Details[0].Actions[0] = "admin"
	s.Details[0].Identifier = "999"
	view := c.Snapshot()
	view.Details[1].Actions[0] = "admin"
	view.Details[0].Type = "https://evil.example/v1"
	want := objectSpec()
	for i, d := range c.Snapshot().Details {
		if d.Type != want.Details[i].Type || d.Identifier != want.Details[i].Identifier || !slices.Equal(d.Actions, want.Details[i].Actions) {
			t.Fatal("caller modified immutable authority")
		}
	}
	requested := c.Snapshot().Details[:1]
	narrowed, err := c.Narrow(c, requested)
	if err != nil {
		t.Fatal(err)
	}
	requested[0].Actions[0] = "write"
	narrowedView := narrowed.Snapshot()
	narrowedView.Details[0].Actions[0] = "admin"
	if !narrowed.Permits(want.Scope, want.Resource, want.Details[0].Type, "123", "read") || narrowed.Permits(want.Scope, want.Resource, want.Details[0].Type, "123", "write") {
		t.Fatal("narrowed result aliased caller memory")
	}
}

func TestObjectCeilingMissingAndEmptyNeverMeanUnrestricted(t *testing.T) {
	c := objectCeiling(t, objectSpec())
	boundEmptySpec := c.Snapshot()
	boundEmptySpec.Details = nil
	empty := objectCeiling(t, boundEmptySpec)
	var zero ObjectCeiling
	if zero.Permits(boundEmptySpec.Scope, boundEmptySpec.Resource, objectSpec().Details[0].Type, "123", "read") || zero.IsSubsetOf(c) || c.IsSubsetOf(empty) {
		t.Fatal("missing/empty ceiling granted authority")
	}
	if !empty.IsSubsetOf(c) {
		t.Fatal("bound denial must be an empty subset")
	}
	for _, missing := range []ObjectCeiling{zero} {
		if _, err := c.Narrow(missing, nil); err == nil {
			t.Fatal("missing current authority accepted")
		}
		if _, err := c.Narrow(c, nil, missing); err == nil {
			t.Fatal("missing credential ceiling accepted")
		}
	}
	for _, inputs := range [][]ObjectCeiling{{empty}, {c, empty}} {
		got, err := c.Narrow(inputs[0], nil, inputs[1:]...)
		if err != nil || len(got.Snapshot().Details) != 0 {
			t.Fatalf("permission removal did not empty authority: %v", err)
		}
	}
	if _, err := c.Narrow(c, []ObjectDetail{}); err == nil {
		t.Fatal("explicit empty request was confused with omission")
	}
}

func TestObjectCeilingRejectsMalformedValues(t *testing.T) {
	changes := map[string]func(*ObjectCeilingSpec){
		"missing tenant":        func(s *ObjectCeilingSpec) { s.Scope.TenantID = "" },
		"missing resource":      func(s *ObjectCeilingSpec) { s.Resource = "" },
		"wildcard resource":     func(s *ObjectCeilingSpec) { s.Resource += "/*" },
		"missing type":          func(s *ObjectCeilingSpec) { s.Details[0].Type = "" },
		"type whitespace":       func(s *ObjectCeilingSpec) { s.Details[0].Type += " " },
		"missing identifier":    func(s *ObjectCeilingSpec) { s.Details[0].Identifier = "" },
		"long identifier":       func(s *ObjectCeilingSpec) { s.Details[0].Identifier = strings.Repeat("x", MaxObjectIdentifierBytes+1) },
		"wildcard identifier":   func(s *ObjectCeilingSpec) { s.Details[0].Identifier = "123*" },
		"question wildcard":     func(s *ObjectCeilingSpec) { s.Details[0].Identifier = "12?" },
		"identifier whitespace": func(s *ObjectCeilingSpec) { s.Details[0].Identifier = " 123" },
		"identifier control":    func(s *ObjectCeilingSpec) { s.Details[0].Identifier = "123\x00" },
		"identifier unicode":    func(s *ObjectCeilingSpec) { s.Details[0].Identifier = "１２３" },
		"missing actions":       func(s *ObjectCeilingSpec) { s.Details[0].Actions = nil },
		"duplicate action":      func(s *ObjectCeilingSpec) { s.Details[0].Actions = []string{"read", "read"} },
		"wildcard action":       func(s *ObjectCeilingSpec) { s.Details[0].Actions = []string{"*"} },
		"action case":           func(s *ObjectCeilingSpec) { s.Details[0].Actions = []string{"READ"} },
		"action whitespace":     func(s *ObjectCeilingSpec) { s.Details[0].Actions = []string{"read write"} },
		"long action":           func(s *ObjectCeilingSpec) { s.Details[0].Actions = []string{strings.Repeat("r", 65)} },
		"duplicate object":      func(s *ObjectCeilingSpec) { s.Details = append(s.Details, s.Details[0]) },
		"split same object": func(s *ObjectCeilingSpec) {
			s.Details = append(s.Details, ObjectDetail{Type: s.Details[0].Type, Identifier: "123", Actions: []string{"write"}})
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := objectSpec()
			change(&s)
			if _, err := NewObjectCeiling(s); !errors.Is(err, ErrInvalidObjectCeiling) {
				t.Fatalf("invalid authority accepted: %v", err)
			}
		})
	}
	s := objectSpec()
	s.Details = nil
	for i := 0; i < MaxObjectDetails; i++ {
		s.Details = append(s.Details, ObjectDetail{Type: objectSpec().Details[0].Type, Identifier: fmt.Sprint(i), Actions: []string{"read"}})
	}
	objectCeiling(t, s)
	s.Details = append(s.Details, ObjectDetail{Type: s.Details[0].Type, Identifier: "overflow", Actions: []string{"read"}})
	if _, err := NewObjectCeiling(s); err == nil {
		t.Fatal("too many details accepted")
	}
	actions := make([]string, 0, MaxObjectActions+1)
	for i := 0; i <= MaxObjectActions; i++ {
		actions = append(actions, fmt.Sprintf("action-%d", i))
	}
	if !ValidObjectActions(actions[:MaxObjectActions]) || ValidObjectActions(actions) {
		t.Fatal("action count bounds incorrect")
	}
}

func maskCeiling(t *testing.T, mask int) ObjectCeiling {
	t.Helper()
	s := objectSpec()
	s.Details = nil
	for object := 0; object < 2; object++ {
		d := ObjectDetail{Type: "https://api.example/types/document/v1", Identifier: fmt.Sprint(123 + object)}
		for action, name := range []string{"read", "write"} {
			if mask&(1<<(object*2+action)) != 0 {
				d.Actions = append(d.Actions, name)
			}
		}
		if len(d.Actions) != 0 {
			s.Details = append(s.Details, d)
		}
	}
	return objectCeiling(t, s)
}

// Exhaust every historical/current/credential combination over two objects and
// two actions. The independent bitset oracle catches tuple recombination and
// authority resurrection without mirroring the production intersection loops.
func TestObjectAttenuationExhaustive(t *testing.T) {
	var ceilings [16]ObjectCeiling
	for mask := range ceilings {
		ceilings[mask] = maskCeiling(t, mask)
	}
	for historical := range ceilings {
		for current := range ceilings {
			for credential := range ceilings {
				got, err := ceilings[historical].Narrow(ceilings[current], nil, ceilings[credential])
				want := ceilings[historical&current&credential]
				if err != nil || !got.IsSubsetOf(want) || !want.IsSubsetOf(got) {
					t.Fatalf("intersection %04b & %04b & %04b widened/lost authority: %v", historical, current, credential, err)
				}
			}
			for requested := 1; requested < len(ceilings); requested++ {
				got, err := ceilings[historical].Narrow(ceilings[current], ceilings[requested].Snapshot().Details)
				allowed := requested & ^(historical&current) == 0
				if (err == nil) != allowed || allowed && (!got.IsSubsetOf(ceilings[requested]) || !ceilings[requested].IsSubsetOf(got)) {
					t.Fatalf("request %04b under %04b & %04b: %v", requested, historical, current, err)
				}
			}
		}
	}
}
