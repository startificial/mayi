package resources

import (
	"errors"
	"strings"
	"testing"

	"github.com/startificial/mayi/internal/domain/grants"
)

func documentProfileSpec() DocumentProfileSpec {
	return DocumentProfileSpec{Scope: grants.Scope{TenantID: "tenant-a", Issuer: "https://auth.example/t/a"}, Resource: "https://api.example/documents", Type: "https://api.example/types/document/v1", Semantics: DocumentV1, Actions: []DocumentAction{{Name: "read", Description: "Read this document"}, {Name: "write", Description: "Change this document"}}}
}
func requestDetails() []grants.ObjectDetail {
	return []grants.ObjectDetail{{Type: documentProfileSpec().Type, Identifier: "123", Actions: []string{"read"}}}
}

func TestDocumentProfileValidatesRegisteredTypesActionsAndScope(t *testing.T) {
	s := documentProfileSpec()
	p, err := NewDocumentProfile(s)
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.ValidateRequest(s.Scope, s.Resource, requestDetails())
	if err != nil || !c.Permits(s.Scope, s.Resource, s.Type, "123", "read") || c.Permits(s.Scope, s.Resource, s.Type, "124", "read") || c.Permits(s.Scope, s.Resource, s.Type, "123", "write") {
		t.Fatalf("invalid object ceiling: %v", err)
	}
	for name, details := range map[string][]grants.ObjectDetail{
		"absent":         nil,
		"empty":          {},
		"unknown type":   {{Type: "https://evil.example/types/document/v1", Identifier: "123", Actions: []string{"read"}}},
		"new version":    {{Type: strings.Replace(s.Type, "/v1", "/v2", 1), Identifier: "123", Actions: []string{"read"}}},
		"unknown action": {{Type: s.Type, Identifier: "123", Actions: []string{"admin"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.ValidateRequest(s.Scope, s.Resource, details); !errors.Is(err, ErrInvalidDocumentRequest) {
				t.Fatalf("unregistered authority accepted: %v", err)
			}
		})
	}
	for _, scope := range []grants.Scope{{TenantID: "tenant-b", Issuer: s.Scope.Issuer}, {TenantID: s.Scope.TenantID, Issuer: s.Scope.Issuer + "/other"}} {
		if _, err := p.ValidateRequest(scope, s.Resource, requestDetails()); err == nil {
			t.Fatal("foreign tenant/issuer accepted")
		}
	}
	if _, err := p.ValidateRequest(s.Scope, s.Resource+"/child", requestDetails()); err == nil {
		t.Fatal("resource prefix matched")
	}
	if _, err := (DocumentProfile{}).ValidateRequest(s.Scope, s.Resource, requestDetails()); err == nil {
		t.Fatal("zero profile accepted")
	}
}

func TestDocumentProfileRegistrationAndImmutability(t *testing.T) {
	for name, change := range map[string]func(*DocumentProfileSpec){
		"scope":       func(s *DocumentProfileSpec) { s.Scope.TenantID = "" },
		"resource":    func(s *DocumentProfileSpec) { s.Resource = "https://api.example/*" },
		"type":        func(s *DocumentProfileSpec) { s.Type = "document" },
		"type query":  func(s *DocumentProfileSpec) { s.Type += "?schema=other" },
		"type user":   func(s *DocumentProfileSpec) { s.Type = "https://user@api.example/v1" },
		"semantics":   func(s *DocumentProfileSpec) { s.Semantics = "document-v2" },
		"actions":     func(s *DocumentProfileSpec) { s.Actions = nil },
		"duplicate":   func(s *DocumentProfileSpec) { s.Actions = append(s.Actions, s.Actions[0]) },
		"description": func(s *DocumentProfileSpec) { s.Actions[0].Description = "" },
		"control":     func(s *DocumentProfileSpec) { s.Actions[0].Description = "read\nsecret" },
	} {
		t.Run(name, func(t *testing.T) {
			s := documentProfileSpec()
			change(&s)
			if _, err := NewDocumentProfile(s); !errors.Is(err, ErrInvalidDocumentProfile) {
				t.Fatalf("invalid registration accepted: %v", err)
			}
		})
	}
	s := documentProfileSpec()
	p, err := NewDocumentProfile(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Actions[0].Name = "admin"
	p.Snapshot().Actions[0].Name = "admin"
	if _, err := p.ValidateRequest(s.Scope, s.Resource, requestDetails()); err != nil {
		t.Fatal("caller mutated profile")
	}
	details := requestDetails()
	c, err := p.ValidateRequest(s.Scope, s.Resource, details)
	if err != nil {
		t.Fatal(err)
	}
	details[0].Actions[0] = "write"
	if c.Permits(s.Scope, s.Resource, s.Type, "123", "write") {
		t.Fatal("caller changed validated ceiling")
	}
}
