package grants

import (
	"slices"
	"testing"
	"time"
)

func revisionSpec() RevisionSpec {
	spec := RevisionSpec{Scope: Scope{TenantID: "tenant-a", Issuer: "https://auth.example/t/a"}, GrantID: "grant-1", Number: 1, ClientID: "client:web", Subject: "user:alice", PrincipalType: "user", Resource: "https://api.example/a", Scopes: []string{"read", "write"}, ExpiresAt: time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)}
	spec.ObjectCeiling, _ = NewObjectCeiling(ObjectCeilingSpec{Scope: spec.Scope, Resource: spec.Resource, Details: []ObjectDetail{{Type: "https://api.example/types/fixture/v1", Identifier: "123", Actions: []string{"read"}}}})
	return spec
}

func TestRevisionIsImmutable(t *testing.T) {
	spec := revisionSpec()
	revision, err := NewRevision(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Scopes[0] = "admin"
	snapshot := revision.Snapshot()
	snapshot.Scopes[1] = "admin"
	got := revision.Snapshot()
	if !slices.Equal(got.Scopes, []string{"read", "write"}) {
		t.Fatalf("revision mutated: %+v", got)
	}
}

func TestObjectRevisionBindsHistoricalAuthority(t *testing.T) {
	spec := revisionSpec()
	objects := objectSpec()
	objects.Scope, objects.Resource = spec.Scope, spec.Resource
	spec.ObjectCeiling = objectCeiling(t, objects)
	old, err := NewRevision(spec)
	if err != nil {
		t.Fatal(err)
	}
	view := old.Snapshot()
	view.ObjectCeiling.Snapshot().Details[0].Actions[0] = "admin"
	objects.Details = append(objects.Details, ObjectDetail{Type: objects.Details[0].Type, Identifier: "125", Actions: []string{"read"}})
	spec.Number++
	spec.ObjectCeiling = objectCeiling(t, objects)
	newer, err := NewRevision(spec)
	if err != nil || old.Snapshot().ObjectCeiling.Equal(newer.Snapshot().ObjectCeiling) || old.Snapshot().ObjectCeiling.Permits(spec.Scope, spec.Resource, objects.Details[0].Type, "125", "read") {
		t.Fatal("new approval enlarged historical object authority", err)
	}
	for _, mutate := range []func(*ObjectCeilingSpec){
		func(s *ObjectCeilingSpec) { s.Scope.TenantID = "other" },
		func(s *ObjectCeilingSpec) { s.Scope.Issuer += "/other" },
		func(s *ObjectCeilingSpec) { s.Resource += "/other" },
		func(s *ObjectCeilingSpec) { s.Details = nil },
	} {
		bad := old.Snapshot()
		ceiling := bad.ObjectCeiling.Snapshot()
		mutate(&ceiling)
		bad.ObjectCeiling = objectCeiling(t, ceiling)
		if _, err := NewRevision(bad); err == nil {
			t.Fatal("foreign/empty object authority rehydrated")
		}
	}

}

func TestHistoricalCeilingSurvivesNewConsentAndCurrentPermissionLoss(t *testing.T) {
	spec := revisionSpec()
	spec.Scopes = []string{"read"}
	revision, err := NewRevision(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revision.Narrow([]string{"read", "admin"}, []string{"admin"}); err == nil {
		t.Fatal("later consent expanded old credential")
	}
	scopes, err := revision.Narrow([]string{"write"}, nil)
	if err != nil || len(scopes) != 0 {
		t.Fatalf("lost permission survived: %v %v", scopes, err)
	}
}

func TestInvalidRevisions(t *testing.T) {
	cases := map[string]func(*RevisionSpec){
		"tenant missing":        func(s *RevisionSpec) { s.Scope.TenantID = "" },
		"revision missing":      func(s *RevisionSpec) { s.Number = 0 },
		"expiry missing":        func(s *RevisionSpec) { s.ExpiresAt = time.Time{} },
		"user namespace":        func(s *RevisionSpec) { s.Subject = "client:web" },
		"machine impersonation": func(s *RevisionSpec) { s.PrincipalType = "machine" },
		"unknown principal":     func(s *RevisionSpec) { s.PrincipalType = "agent" },
		"duplicate scope":       func(s *RevisionSpec) { s.Scopes = []string{"read", "read"} },
		"scope whitespace":      func(s *RevisionSpec) { s.Scopes = []string{"read write"} },
		"scope quote":           func(s *RevisionSpec) { s.Scopes = []string{"read\""} },
		"scope backslash":       func(s *RevisionSpec) { s.Scopes = []string{"read\\"} },
		"scope unicode":         func(s *RevisionSpec) { s.Scopes = []string{"réad"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			spec := revisionSpec()
			change(&spec)
			if _, err := NewRevision(spec); err == nil {
				t.Fatal("invalid revision accepted")
			}
		})
	}
	spec := revisionSpec()
	spec.PrincipalType = "machine"
	spec.Subject = spec.ClientID
	if _, err := NewRevision(spec); err != nil {
		t.Fatalf("valid machine rejected: %v", err)
	}
}

func TestIncrementalApprovalUnionsCompleteTuplesWithoutMutatingHistory(t *testing.T) {
	spec := revisionSpec()
	old, err := NewRevision(spec)
	if err != nil {
		t.Fatal(err)
	}
	requested := spec
	requested.Scopes = []string{"admin"}
	requested.ObjectCeiling, _ = NewObjectCeiling(ObjectCeilingSpec{Scope: spec.Scope, Resource: spec.Resource, Details: []ObjectDetail{{Type: "https://api.example/types/fixture/v1", Identifier: "124", Actions: []string{"write"}}}})
	newer, err := old.Extend(requested)
	if err != nil {
		t.Fatal(err)
	}
	if newer.Snapshot().Number != 2 || newer.Snapshot().GrantID != spec.GrantID || !newer.Snapshot().ObjectCeiling.Permits(spec.Scope, spec.Resource, "https://api.example/types/fixture/v1", "124", "write") || old.Snapshot().ObjectCeiling.Permits(spec.Scope, spec.Resource, "https://api.example/types/fixture/v1", "124", "write") {
		t.Fatal("incremental revision changed historical authority")
	}
	requested.Subject = "user:bob"
	if _, err := old.Extend(requested); err == nil {
		t.Fatal("approval switched principal")
	}
	requested = spec
	requested.Resource = "https://other.example"
	if _, err := old.Extend(requested); err == nil {
		t.Fatal("approval switched resource")
	}
}
