package resources

import "github.com/startificial/mayi/internal/domain/grants"

// MaxObjectRequestProfiles bounds the trusted vocabulary projection supplied
// for one request. It is independent of the number of requested objects.
const MaxObjectRequestProfiles = 32

// ValidateObjectRequest selects each exact type from one trusted resource's
// vocabulary. It validates complete tuples; actions never bleed across types.
// This is schema validation, not client or principal authorization.
func ValidateObjectRequest(scope grants.Scope, resource string, profiles []ObjectProfile, details []grants.ObjectDetail) (grants.ObjectCeiling, error) {
	if len(profiles) == 0 || len(profiles) > MaxObjectRequestProfiles || len(details) == 0 {
		return grants.ObjectCeiling{}, ErrInvalidObjectRequest
	}
	byType := make(map[string]ObjectProfile, len(profiles))
	for _, profile := range profiles {
		s := profile.Snapshot()
		if _, err := NewObjectProfile(s); err != nil || s.Scope != scope || s.Resource != resource {
			return grants.ObjectCeiling{}, ErrInvalidObjectRequest
		}
		if _, duplicate := byType[s.Type]; duplicate {
			return grants.ObjectCeiling{}, ErrInvalidObjectRequest
		}
		byType[s.Type] = profile
	}
	ceiling, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: scope, Resource: resource, Details: details})
	if err != nil {
		return grants.ObjectCeiling{}, ErrInvalidObjectRequest
	}
	for _, detail := range details {
		profile, ok := byType[detail.Type]
		if !ok {
			return grants.ObjectCeiling{}, ErrInvalidObjectRequest
		}
		if _, err := profile.ValidateRequest(scope, resource, []grants.ObjectDetail{detail}); err != nil {
			return grants.ObjectCeiling{}, ErrInvalidObjectRequest
		}
	}
	return ceiling, nil
}
