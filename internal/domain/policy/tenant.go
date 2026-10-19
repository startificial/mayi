// Package policy contains tenant policy invariants, without ambient effects.
package policy

type Tenant struct {
	RefreshIdleSeconds, RefreshAbsoluteSeconds int
	Version                                    uint64
	MaxAccessTokenSeconds                      int
	MaxGrantSeconds                            int
	RequireBinding                             bool
}

func DefaultTenant() Tenant {
	return Tenant{Version: 1, MaxAccessTokenSeconds: 600, MaxGrantSeconds: 86400, RequireBinding: true}
}

func (p Tenant) Valid() bool {
	return p.RefreshIdle() >= 60 && p.RefreshIdle() <= 2592000 && p.RefreshAbsolute() >= p.RefreshIdle() && p.RefreshAbsolute() <= 31622400 && p.Version > 0 && p.MaxAccessTokenSeconds >= 60 && p.MaxAccessTokenSeconds <= 900 &&
		p.MaxGrantSeconds >= p.MaxAccessTokenSeconds && p.MaxGrantSeconds <= 366*24*60*60
}

// Omitted configuration uses the same bounded defaults as a fresh tenant.
func (p Tenant) RefreshIdle() int {
	if p.RefreshIdleSeconds == 0 && p.RefreshAbsoluteSeconds == 0 {
		return 86400
	}
	return p.RefreshIdleSeconds
}
func (p Tenant) RefreshAbsolute() int {
	if p.RefreshIdleSeconds == 0 && p.RefreshAbsoluteSeconds == 0 {
		return 2592000
	}
	return p.RefreshAbsoluteSeconds
}
