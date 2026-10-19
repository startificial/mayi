package authorization

import (
	"strings"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/domain/grants"
)

func TestPushedRequestIsImmutableBoundedAndSingleUse(t *testing.T) {
	w, _ := example()
	w.Request.State = "fresh-client-state-16"
	var err error
	w.Request.ObjectCeiling, err = grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: w.Request.TenantIssuer, Resource: w.Request.ResourceURI, Details: []grants.ObjectDetail{{Type: "https://api.example/types/fixture/v1", Identifier: "workflow:123", Actions: []string{"read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	spec := PushedSpec{ID: "pushed-1", ReferenceHash: strings.Repeat("d", 64), Request: w.Request, PolicyVersion: 1, CreatedAt: w.CreatedAt, ExpiresAt: w.CreatedAt.Add(PushedLifetime)}
	p, err := NewPushed(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Request.PermissionScopes[0] = "write"
	snapshot := p.Snapshot()
	snapshot.Request.PermissionScopes[0] = "write"
	if p.Snapshot().Request.PermissionScopes[0] != "read" {
		t.Fatal("pushed request aliased input or output")
	}
	if p.ActiveAt(w.CreatedAt.Add(-time.Nanosecond)) || !p.ActiveAt(w.CreatedAt) || p.ActiveAt(w.CreatedAt.Add(PushedLifetime)) {
		t.Fatal("pushed lifetime bounds")
	}
	now := w.CreatedAt.Add(time.Second)
	next, workflow, err := p.Begin("workflow-1", strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), now)
	if err != nil || next.ActiveAt(now) || !workflow.Snapshot().Request.Equal(p.Snapshot().Request) || workflow.Snapshot().PushedRequestHash != p.Snapshot().ReferenceHash {
		t.Fatal("consumption changed snapshot or remained active", err)
	}
	if _, _, err := next.Begin("replay", strings.Repeat("e", 64), strings.Repeat("b", 64), strings.Repeat("f", 64), now); err == nil {
		t.Fatal("consumed reference reused")
	}
	if _, _, err := p.Begin("collision", p.Snapshot().ReferenceHash, strings.Repeat("b", 64), strings.Repeat("c", 64), now); err == nil {
		t.Fatal("reference reused as workflow credential")
	}
	for _, mode := range []string{"long lifetime", "missing objects", "partial consumed", "consumed expired", "short state", "bad provenance"} {
		t.Run(mode, func(t *testing.T) {
			s := p.Snapshot()
			switch mode {
			case "long lifetime":
				s.ExpiresAt = s.ExpiresAt.Add(time.Second)
			case "missing objects":
				s.Request.ObjectCeiling = grants.ObjectCeiling{}
			case "partial consumed":
				s.ConsumedAt = now
			case "consumed expired":
				s.AuthorizationHash = strings.Repeat("a", 64)
				s.ConsumedAt = s.ExpiresAt
			case "short state":
				s.Request.State = "short"
			case "bad provenance":
				s.ReferenceHash = "unknown"
			}
			if _, err := NewPushed(s); err == nil {
				t.Fatal("invalid pushed request accepted")
			}
		})
	}
}
