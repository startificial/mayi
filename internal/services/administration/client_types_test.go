package administration

import (
	"context"
	"errors"
	"testing"

	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
)

func TestClientTypesValidateBeforeWriteAndKeepTrustedProfileBinding(t *testing.T) {
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	actor := Actor{ID: "admin", Scope: scope, Permissions: []string{"clients:write"}}
	typ := "https://api.example/types/workflow/v1"
	spec := resources.ObjectProfileSpec{Scope: scope, Resource: "https://api.example", Type: typ, Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read workflow"}}}
	for _, mode := range []string{"missing types", "foreign profile tenant", "foreign profile issuer", "foreign audience", "wrong type", "valid", "commit failure"} {
		t.Run(mode, func(t *testing.T) {
			definition := spec
			input := clients.Client{ID: "web", Name: "Web", RedirectURIs: []string{"https://app.example/cb"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{typ}, AccessTokenSeconds: 300, Enabled: true}
			f := &fake{t: t, p: policy.DefaultTenant(), resource: resources.Resource{ID: "api", URI: spec.Resource, AccessTokenSeconds: 300}}
			switch mode {
			case "missing types":
				input.AuthorizationDetailsTypes = nil
				f.denyAccess = true
			case "foreign profile tenant":
				definition.Scope.TenantID = "b"
			case "foreign profile issuer":
				definition.Scope.Issuer = "https://other.example/t/a"
			case "foreign audience":
				definition.Resource = "https://another.example"
			case "wrong type":
				definition.Type += "/other"
			case "commit failure":
				f.commitErr = ErrUnavailable
			}
			var err error
			f.profile, err = resources.NewObjectProfile(definition)
			if err != nil {
				t.Fatal(err)
			}
			s, _ := New(f, f, f)
			err = s.CreateClient(context.Background(), actor, scope, input)
			switch mode {
			case "valid":
				if err != nil || f.creates != 1 || f.audits != 1 {
					t.Fatal("valid client was not created/audited", err)
				}
			case "commit failure":
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal("uncommitted client acknowledged", err)
				}
			default:
				if !errors.Is(err, ErrInvalid) || f.creates != 0 || f.audits != 0 {
					t.Fatal("invalid type metadata reached mutation", err)
				}
			}
		})
	}
}
