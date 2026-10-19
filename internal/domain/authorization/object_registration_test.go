package authorization

import (
	"testing"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

func TestObjectRegistrationChecksExactClientTypeAudienceAndVocabulary(t *testing.T) {
	workflow, current := example()
	request := workflow.Request
	typ := "https://api.example/types/fixture/v1"
	spec := resources.ObjectProfileSpec{Scope: request.TenantIssuer, Resource: request.ResourceURI, Type: typ, Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read object"}}}
	profile, err := resources.NewObjectProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	current.ObjectProfiles = []resources.ObjectProfile{profile}
	request.ObjectCeiling, err = profile.ValidateRequest(request.TenantIssuer, request.ResourceURI, []grants.ObjectDetail{{Type: typ, Identifier: "workflow:123", Actions: []string{"read"}}})
	if err != nil || !request.MatchesObjectRegistration(current) {
		t.Fatal("registration either rejected vocabulary or enabled consent", err)
	}
	for _, mode := range []string{"missing authority", "missing profiles", "duplicate profiles", "unregistered type", "unregistered action", "foreign tenant", "foreign issuer", "foreign audience", "client type absent", "client resource absent", "disabled client"} {
		t.Run(mode, func(t *testing.T) {
			r, projection, definition := request, current, spec
			projection.Client.AuthorizationDetailsTypes = append([]string(nil), current.Client.AuthorizationDetailsTypes...)
			switch mode {
			case "missing authority":
				r.ObjectCeiling = grants.ObjectCeiling{}
			case "missing profiles":
				projection.ObjectProfiles = nil
			case "duplicate profiles":
				projection.ObjectProfiles = []resources.ObjectProfile{profile, profile}
			case "client type absent":
				projection.Client.AuthorizationDetailsTypes = []string{typ + "/other"}
			case "client resource absent":
				projection.Client.Resources = []string{"other"}
			case "disabled client":
				projection.Client.Enabled = false
			case "foreign tenant", "foreign issuer", "foreign audience":
				if mode == "foreign tenant" {
					definition.Scope.TenantID = "b"
				} else if mode == "foreign issuer" {
					definition.Scope.Issuer = "https://other.example/t/a"
				} else {
					definition.Resource = "https://other.example"
				}
				p, err := resources.NewObjectProfile(definition)
				if err != nil {
					t.Fatal(err)
				}
				projection.ObjectProfiles = []resources.ObjectProfile{p}
			default:
				detail := grants.ObjectDetail{Type: typ, Identifier: "workflow:123", Actions: []string{"read"}}
				if mode == "unregistered type" {
					detail.Type += "/other"
				} else {
					detail.Actions = []string{"delete"}
				}
				r.ObjectCeiling, err = grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: r.TenantIssuer, Resource: r.ResourceURI, Details: []grants.ObjectDetail{detail}})
				if err != nil {
					t.Fatal(err)
				}
			}
			if r.MatchesObjectRegistration(projection) {
				t.Fatal("invalid object registration accepted")
			}
		})
	}
}
