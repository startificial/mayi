package grants

import (
	"slices"
	"testing"
	"time"
)

func revisionSpec() RevisionSpec {
	return RevisionSpec{Scope: Scope{TenantID: "tenant-a", Issuer: "https://auth.example/t/a"}, GrantID: "grant-1", Number: 1, ClientID: "client:web", Subject: "user:alice", PrincipalType: "user", Resource: "https://api.example/a", Scopes: []string{"read", "write"}, ExpiresAt: time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)}
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
