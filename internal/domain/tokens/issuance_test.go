package tokens

import (
	"testing"
	"time"

	"github.com/startificial/mayi/internal/domain/grants"
)

func TestDeriveCapsEveryDeadlineAndKeepsExactRevision(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	spec := grants.RevisionSpec{Scope: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, GrantID: "g1", Number: 7, ClientID: "client:web", Subject: "user:alice", PrincipalType: "user", Resource: "https://api.example/a", Scopes: []string{"read"}, ExpiresAt: now.Add(4 * time.Minute)}
	spec.ObjectCeiling, _ = grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: spec.Scope, Resource: spec.Resource, Details: []grants.ObjectDetail{{Type: "https://api.example/types/fixture/v1", Identifier: "123", Actions: []string{"read"}}}})
	revision, err := grants.NewRevision(spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := DeriveObjects(revision, []string{"read", "admin"}, nil, spec.ObjectCeiling, "id-1", "key-1", now, 10*time.Minute, now.Add(2*time.Minute), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !result.ExpiresAt.Equal(now.Add(time.Minute)) || result.Revision != 7 || result.GrantID != "g1" || result.Resource != "https://api.example/a" || result.BindingThumbprint != "key-1" || result.PrincipalType != "user" {
		t.Fatalf("incorrect derived authority: %+v", result)
	}
	for name, deadline := range map[string]time.Time{"expired": now, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			if _, err := DeriveObjects(revision, []string{"read"}, nil, spec.ObjectCeiling, "id", "", now, time.Minute, deadline); err == nil {
				t.Fatal("invalid deadline accepted")
			}
		})
	}
	if _, err := DeriveObjects(revision, []string{"read"}, []string{"admin"}, spec.ObjectCeiling, "id", "", now, time.Minute); err == nil {
		t.Fatal("scope expansion accepted")
	}
	if _, err := DeriveObjects(revision, nil, nil, spec.ObjectCeiling, "id", "", now, time.Minute); err == nil {
		t.Fatal("empty current authorization accepted")
	}
	if _, err := DeriveObjects(grants.Revision{}, []string{"read"}, nil, spec.ObjectCeiling, "id", "", now, time.Minute); err == nil {
		t.Fatal("zero revision accepted")
	}
}

func TestRevisionCannotOmitRequiredObjectAuthority(t *testing.T) {
	now := time.Unix(1700000000, 0)
	spec := grants.RevisionSpec{Scope: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, GrantID: "g", Number: 1, ClientID: "client", Subject: "user:alice", PrincipalType: "user", Resource: "https://api.example", Scopes: []string{"read"}, ExpiresAt: now.Add(time.Hour)}
	if _, err := grants.NewRevision(spec); err == nil {
		t.Fatal("scope-only revision accepted")
	}
}
