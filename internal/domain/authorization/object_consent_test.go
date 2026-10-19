package authorization

import (
	"strings"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/domain/grants"
)

func objectConsentExample(t *testing.T) (Transaction, ObjectConsentSpec) {
	t.Helper()
	w, _ := example()
	var err error
	w.Request.ObjectCeiling, err = grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: w.Request.TenantIssuer, Resource: w.Request.ResourceURI, Details: []grants.ObjectDetail{{Type: "https://api.example/types/file/v1", Identifier: "file:123", Actions: []string{"read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	w.PushedRequestHash = strings.Repeat("d", 64)
	workflow, err := New(w)
	if err != nil {
		t.Fatal(err)
	}
	return workflow, ObjectConsentSpec{AuthorizationHash: w.HandleHash, ClientID: w.Request.ClientID, Subject: "user:alice", PermissionVersion: 7, Ceiling: w.Request.ObjectCeiling, Objects: []ConsentObject{{Type: "https://api.example/types/file/v1", Identifier: "file:123", Name: "Resource-owned file name"}}}
}

func TestObjectApprovalRequiresUnchangedPresentationAndPermissionVersion(t *testing.T) {
	w, spec := objectConsentExample(t)
	w, err := w.BindSession(w.Snapshot().ConsentSessionHash, w.Snapshot().CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewObjectConsentProjection(spec)
	if err != nil {
		t.Fatal(err)
	}
	now := w.Snapshot().CreatedAt.Add(time.Second)
	approved, revision, err := w.ApproveObjects(p, p, spec.Subject, "grant-1", strings.Repeat("f", 64), now, time.Hour)
	if err != nil || approved.Snapshot().Status != Approved || !revision.Snapshot().ObjectCeiling.Equal(spec.Ceiling) {
		t.Fatal("exact object approval failed", err)
	}
	for _, mode := range []string{"missing presentation", "version", "label", "subject", "workflow", "permission expansion"} {
		t.Run(mode, func(t *testing.T) {
			s := p.Snapshot()
			switch mode {
			case "version":
				s.PermissionVersion++
			case "label":
				s.Objects[0].Name = "Different title"
			case "subject":
				s.Subject = "user:bob"
			case "workflow":
				s.AuthorizationHash = strings.Repeat("e", 64)
			case "permission expansion":
				c := s.Ceiling.Snapshot()
				c.Details[0].Actions = append(c.Details[0].Actions, "write")
				var err error
				s.Ceiling, err = grants.NewObjectCeiling(c)
				if err != nil {
					t.Fatal(err)
				}
			}
			fresh, err := NewObjectConsentProjection(s)
			if err != nil {
				t.Fatal(err)
			}
			presented := p
			if mode == "missing presentation" {
				presented = ObjectConsentProjection{}
			}
			if _, _, err := w.ApproveObjects(presented, fresh, spec.Subject, "grant-1", strings.Repeat("f", 64), now, time.Hour); err == nil {
				t.Fatal("changed presentation approved")
			}
		})
	}
	spec.PermissionVersion = MaxPermissionVersion + 1
	if _, err := NewObjectConsentProjection(spec); err == nil {
		t.Fatal("unsupported permission version accepted")
	}
}

func TestObjectConsentProjectionBindsExactWorkflowActorAndObjects(t *testing.T) {
	w, s := objectConsentExample(t)
	p, err := NewObjectConsentProjection(s)
	if err != nil || !p.Matches(w, s.Subject) || p.Matches(w, "user:bob") {
		t.Fatal("projection correlation", err)
	}
	s.Objects[0].Name = "changed"
	p.Snapshot().Objects[0].Name = "changed"
	if p.Snapshot().Objects[0].Name != "Resource-owned file name" {
		t.Fatal("display snapshot aliased")
	}
	for _, mode := range []string{"hash", "client", "subject", "version", "ceiling", "missing display", "extra display", "duplicate display", "foreign target", "foreign type", "unsafe name"} {
		t.Run(mode, func(t *testing.T) {
			_, spec := objectConsentExample(t)
			switch mode {
			case "hash":
				spec.AuthorizationHash = "raw"
			case "client":
				spec.ClientID = ""
			case "subject":
				spec.Subject = ""
			case "version":
				spec.PermissionVersion = 0
			case "ceiling":
				spec.Ceiling = grants.ObjectCeiling{}
			case "missing display":
				spec.Objects = nil
			case "extra display", "duplicate display":
				spec.Objects = append(spec.Objects, spec.Objects[0])
			case "foreign target":
				spec.Objects[0].Identifier = "file:124"
			case "foreign type":
				spec.Objects[0].Type += "/other"
			case "unsafe name":
				spec.Objects[0].Name = "hidden\ntext"
			}
			if _, err := NewObjectConsentProjection(spec); err == nil {
				t.Fatal("invalid projection accepted")
			}
		})
	}
	for _, mode := range []string{"other workflow", "no PAR", "other client", "other scope", "other authority"} {
		t.Run(mode, func(t *testing.T) {
			spec := w.Snapshot()
			switch mode {
			case "other workflow":
				spec.HandleHash = strings.Repeat("e", 64)
			case "no PAR":
				spec.PushedRequestHash = ""
			case "other client":
				spec.Request.ClientID = "other"
			case "other scope", "other authority":
				c := spec.Request.ObjectCeiling.Snapshot()
				if mode == "other scope" {
					spec.Request.TenantIssuer.TenantID = "b"
					c.Scope = spec.Request.TenantIssuer
				} else {
					c.Details[0].Actions = []string{"write"}
				}
				var err error
				spec.Request.ObjectCeiling, err = grants.NewObjectCeiling(c)
				if err != nil {
					t.Fatal(err)
				}
			}
			other, err := New(spec)
			if err != nil {
				t.Fatal(err)
			}
			if p.Matches(other, "user:alice") {
				t.Fatal("projection applied to another request")
			}
		})
	}
}
