package administration

import (
	"context"
	"errors"
	"testing"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

func TestObjectRegistrationValidatesBindingAndReturnsOnlyCommittedState(t *testing.T) {
	ctx := context.Background()
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	actor := Actor{ID: "admin", Scope: scope, Permissions: []string{"resources:write", "resources:read"}}
	spec := resources.ObjectProfileSpec{Scope: scope, Resource: "https://api.example", Type: "https://api.example/types/workflow/v1", Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "execute", Description: "Execute workflow"}}}
	for _, mode := range []string{"foreign scope", "different audience", "unknown semantics", "duplicate action", "valid", "commit failure"} {
		t.Run(mode, func(t *testing.T) {
			input := spec
			input.Actions = append([]resources.ObjectAction(nil), spec.Actions...)
			f := &fake{t: t, resource: resources.Resource{URI: spec.Resource}}
			s, _ := New(f, f, f)
			switch mode {
			case "foreign scope":
				input.Scope.TenantID = "b"
				f.denyAccess = true
			case "different audience":
				input.Resource = "https://another.example"
			case "unknown semantics":
				input.Semantics = "allow-all"
				f.denyAccess = true
			case "duplicate action":
				input.Actions = append(input.Actions, input.Actions[0])
				f.denyAccess = true
			case "commit failure":
				f.commitErr = ErrUnavailable
			}
			err := s.RegisterObjectProfile(ctx, actor, scope, "api", input)
			switch mode {
			case "valid":
				if err != nil || f.creates != 1 || f.audits != 1 {
					t.Fatal("registration was not audited", err)
				}
				got, err := s.ObjectProfile(ctx, actor, scope, "api", spec.Type)
				if err != nil || got.Snapshot().Type != spec.Type {
					t.Fatal("registered profile not returned", err)
				}
			case "commit failure":
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal("uncommitted registration acknowledged", err)
				}
				if got, err := s.ObjectProfile(ctx, actor, scope, "api", spec.Type); !errors.Is(err, ErrUnavailable) || got.Snapshot().Type != "" {
					t.Fatal("uncommitted read escaped", err)
				}
			default:
				if !errors.Is(err, ErrInvalid) || f.creates != 0 || f.audits != 0 {
					t.Fatal("invalid registration changed state", err)
				}
			}
		})
	}
}
