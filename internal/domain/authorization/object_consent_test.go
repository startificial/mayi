package authorization

import (
	"strings"
	"testing"

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
