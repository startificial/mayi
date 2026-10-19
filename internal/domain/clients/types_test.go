package clients_test

import (
	"fmt"
	"testing"

	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

func TestClientRequiresBoundedExactAuthorizationDetailsTypes(t *testing.T) {
	typ := "https://api.example/types/workflow/v1"
	c := clients.Client{ID: "web", Name: "Web", RedirectURIs: []string{"https://app.example/cb"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{typ}, AccessTokenSeconds: 300, Enabled: true}
	if !c.Valid() {
		t.Fatal("valid client rejected")
	}
	for _, types := range [][]string{nil, {}, {typ, typ}, {"http://api.example/type"}, {"https://api.example/types/*"}, {typ + "#fragment"}} {
		invalid := c
		invalid.AuthorizationDetailsTypes = types
		if invalid.Valid() {
			t.Fatal("invalid or missing types accepted", types)
		}
	}
	for i := range clients.MaxAuthorizationDetailsTypes {
		c.AuthorizationDetailsTypes = append(c.AuthorizationDetailsTypes, fmt.Sprintf("https://api.example/types/version%d", i))
	}
	if c.Valid() {
		t.Fatal("unbounded client types accepted")
	}
	c.AuthorizationDetailsTypes = c.AuthorizationDetailsTypes[:clients.MaxAuthorizationDetailsTypes]
	if !c.Valid() {
		t.Fatal("maximum supported type list rejected")
	}
	c.AuthorizationDetailsTypes = []string{typ}
	p, err := resources.NewObjectProfile(resources.ObjectProfileSpec{Scope: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, Resource: "https://api.example", Type: typ, Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read object"}}})
	resource := resources.Resource{ID: "api", URI: "https://api.example"}
	if err != nil || !c.AllowsObjectProfile(resource, p) || c.AllowsObjectProfile(resources.Resource{ID: "another", URI: resource.URI}, p) || c.AllowsObjectProfile(resources.Resource{ID: resource.ID, URI: "https://other.example"}, p) {
		t.Fatal("profile/resource allowlist failed", err)
	}
	c.AuthorizationDetailsTypes = []string{typ + "/different"}
	if c.AllowsObjectProfile(resource, p) || c.AllowsObjectProfile(resource, resources.ObjectProfile{}) {
		t.Fatal("unknown profile accepted")
	}
}
