// Package policy contains tenant policy invariants, without ambient effects.
package policy

type Tenant struct {
	Version               uint64
	MaxAccessTokenSeconds int
	MaxGrantSeconds       int
	RequireBinding        bool
}

func DefaultTenant() Tenant {
	return Tenant{Version: 1, MaxAccessTokenSeconds: 600, MaxGrantSeconds: 86400, RequireBinding: true}
}

func (p Tenant) Valid() bool {
	return p.Version > 0 && p.MaxAccessTokenSeconds >= 60 && p.MaxAccessTokenSeconds <= 900 &&
		p.MaxGrantSeconds >= p.MaxAccessTokenSeconds && p.MaxGrantSeconds <= 366*24*60*60
}
