package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/startificial/mayi/internal/domain/grants"
)

func TestObjectRequestKeepsVocabularyAndAuthoritySeparateAcrossTypes(t *testing.T) {
	s := objectProfileSpec()
	first, err := NewObjectProfile(s)
	if err != nil {
		t.Fatal(err)
	}
	secondSpec := s
	secondSpec.Type += "/other"
	secondSpec.Actions = []ObjectAction{{Name: "execute", Description: "Execute workflow"}}
	second, err := NewObjectProfile(secondSpec)
	if err != nil {
		t.Fatal(err)
	}
	profiles := []ObjectProfile{first, second}
	details := append(requestDetails(), grants.ObjectDetail{Type: secondSpec.Type, Identifier: "123", Actions: []string{"execute"}})
	ceiling, err := ValidateObjectRequest(s.Scope, s.Resource, profiles, details)
	if err != nil || !ceiling.Permits(s.Scope, s.Resource, s.Type, "123", "read") || !ceiling.Permits(s.Scope, s.Resource, secondSpec.Type, "123", "execute") || ceiling.Permits(s.Scope, s.Resource, s.Type, "123", "execute") || ceiling.Permits(s.Scope, s.Resource, secondSpec.Type, "123", "read") {
		t.Fatal("type/action tuples were combined", err)
	}
	details[1].Actions[0] = "read"
	if ceiling.Permits(s.Scope, s.Resource, secondSpec.Type, "123", "read") {
		t.Fatal("caller changed validated authority")
	}
	if out, err := ValidateObjectRequest(s.Scope, s.Resource, profiles, details); !errors.Is(err, ErrInvalidObjectRequest) || !out.IsZero() {
		t.Fatal("action borrowed from another type", err)
	}
	for _, mode := range []string{"absent", "zero", "duplicate", "foreign tenant", "foreign issuer", "foreign audience", "unrequested foreign profile", "unknown type", "duplicate target", "no details"} {
		t.Run(mode, func(t *testing.T) {
			ps := []ObjectProfile{first}
			ds := requestDetails()
			bad := s
			switch mode {
			case "absent":
				ps = nil
			case "zero":
				ps = []ObjectProfile{{}}
			case "duplicate":
				ps = append(ps, first)
			case "unknown type":
				ds[0].Type = secondSpec.Type
			case "duplicate target":
				ds = append(ds, ds[0])
			case "no details":
				ds = nil
			default:
				switch mode {
				case "foreign tenant":
					bad.Scope.TenantID = "other"
				case "foreign issuer":
					bad.Scope.Issuer += "/other"
				default:
					bad.Resource += "/other"
				}
				p, err := NewObjectProfile(bad)
				if err != nil {
					t.Fatal(err)
				}
				ps = []ObjectProfile{p}
				if mode == "unrequested foreign profile" {
					ps = []ObjectProfile{first, p}
				}
			}
			if out, err := ValidateObjectRequest(s.Scope, s.Resource, ps, ds); !errors.Is(err, ErrInvalidObjectRequest) || !out.IsZero() {
				t.Fatal("invalid vocabulary projection accepted", err)
			}
		})
	}
}

func TestObjectRequestVocabularyProjectionBound(t *testing.T) {
	s := objectProfileSpec()
	var profiles []ObjectProfile
	for i := range MaxObjectRequestProfiles + 1 {
		s.Type = fmt.Sprintf("https://api.example/types/type-%d/v1", i)
		p, err := NewObjectProfile(s)
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, p)
	}
	details := []grants.ObjectDetail{{Type: profiles[0].Snapshot().Type, Identifier: "123", Actions: []string{"read"}}}
	if _, err := ValidateObjectRequest(s.Scope, s.Resource, profiles[:MaxObjectRequestProfiles], details); err != nil {
		t.Fatal("maximum vocabulary projection rejected", err)
	}
	if _, err := ValidateObjectRequest(s.Scope, s.Resource, profiles, details); err == nil {
		t.Fatal("unbounded vocabulary projection accepted")
	}
}
