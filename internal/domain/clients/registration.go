package clients

import "slices"

// RegistrationPolicy controls admission, not existing grants or object access.
// An absent stored policy uses the administrator-only default. CIMD admission is a
// separate capability and must not be inferred from self-asserted DCR metadata.
type RegistrationPolicy struct {
	Version                              uint64
	Mode                                 string
	Resources, AuthorizationDetailsTypes []string
	MaxClients, AccessTokenSeconds       int
	RequireInitialAccess                 bool
}

func DefaultRegistrationPolicy() RegistrationPolicy {
	return RegistrationPolicy{Version: 1, Mode: "admin_only"}
}

func (p RegistrationPolicy) Valid() bool {
	if p.Version == 0 {
		return false
	}
	if p.Mode == "admin_only" {
		return len(p.Resources) == 0 && len(p.AuthorizationDetailsTypes) == 0 && p.MaxClients == 0 && p.AccessTokenSeconds == 0 && !p.RequireInitialAccess
	}
	if p.Mode != "open" || p.MaxClients < 1 || p.MaxClients > 10000 {
		return false
	}
	return (Client{ID: "registration", Name: "Registration", AuthMethod: "none", Enabled: true, RedirectURIs: []string{"https://registration.example/callback"}, Resources: p.Resources, AuthorizationDetailsTypes: p.AuthorizationDetailsTypes, AccessTokenSeconds: p.AccessTokenSeconds}).Valid()
}

type PublicRegistration struct {
	Name, ApplicationType                              string
	RedirectURIs, Resources, AuthorizationDetailsTypes []string
}

// Client admits only public interactive clients with mandatory sender binding.
// Self-asserted names and callbacks never establish publisher trust.
func (p RegistrationPolicy) Client(id string, r PublicRegistration) (Client, bool) {
	c := Client{ID: id, Name: r.Name, ApplicationType: r.ApplicationType, RedirectURIs: slices.Clone(r.RedirectURIs), Resources: slices.Clone(r.Resources), AuthorizationDetailsTypes: slices.Clone(r.AuthorizationDetailsTypes), AccessTokenSeconds: p.AccessTokenSeconds, AuthMethod: "none", Enabled: true, RequireBinding: true}
	if !p.Valid() || p.Mode != "open" || !c.Valid() {
		return Client{}, false
	}
	for _, resource := range c.Resources {
		if !slices.Contains(p.Resources, resource) {
			return Client{}, false
		}
	}
	for _, typ := range c.AuthorizationDetailsTypes {
		if !slices.Contains(p.AuthorizationDetailsTypes, typ) {
			return Client{}, false
		}
	}
	return c, true
}
