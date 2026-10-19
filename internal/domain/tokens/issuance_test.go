package tokens

import (
	"testing"
	"time"

	"github.com/startificial/mayi/internal/domain/grants"
)

func TestDeriveCapsEveryDeadlineAndKeepsExactRevision(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	revision, err := grants.NewRevision(grants.RevisionSpec{Scope: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, GrantID: "g1", Number: 7, ClientID: "client:web", Subject: "user:alice", PrincipalType: "user", Resource: "https://api.example/a", Scopes: []string{"read"}, ExpiresAt: now.Add(4 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Derive(revision, []string{"read", "admin"}, nil, "id-1", "key-1", now, 10*time.Minute, now.Add(2*time.Minute), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !result.ExpiresAt.Equal(now.Add(time.Minute)) || result.Revision != 7 || result.GrantID != "g1" || result.Resource != "https://api.example/a" || result.BindingThumbprint != "key-1" || result.PrincipalType != "user" {
		t.Fatalf("incorrect derived authority: %+v", result)
	}
	for name, deadline := range map[string]time.Time{"expired": now, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			if _, err := Derive(revision, []string{"read"}, nil, "id", "", now, time.Minute, deadline); err == nil {
				t.Fatal("invalid deadline accepted")
			}
		})
	}
	if _, err := Derive(revision, []string{"read"}, []string{"admin"}, "id", "", now, time.Minute); err == nil {
		t.Fatal("scope expansion accepted")
	}
	if _, err := Derive(revision, nil, nil, "id", "", now, time.Minute); err == nil {
		t.Fatal("empty current authorization accepted")
	}
	if _, err := Derive(grants.Revision{}, []string{"read"}, nil, "id", "", now, time.Minute); err == nil {
		t.Fatal("zero revision accepted")
	}
}

func TestScopeOnlyDerivationCannotDropObjectRestrictions(t *testing.T) {
	now := time.Unix(1700000000, 0)
	spec := grants.RevisionSpec{Scope: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, GrantID: "g", Number: 1, ClientID: "client", Subject: "user:alice", PrincipalType: "user", Resource: "https://api.example", Scopes: []string{"read"}, ExpiresAt: now.Add(time.Hour)}
	var err error
	spec.ObjectCeiling, err = grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: spec.Scope, Resource: spec.Resource, Details: []grants.ObjectDetail{{Type: "https://api.example/types/project/v1", Identifier: "project:123", Actions: []string{"read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := grants.NewRevision(spec)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Derive(revision, []string{"read"}, nil, "id", "", now, time.Minute); err == nil || result.ID != "" {
		t.Fatal("scope-only derivation lost object restrictions")
	}
}
