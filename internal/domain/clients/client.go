// Package clients defines registered public web clients and vocabulary ceilings.
package clients

import (
	"slices"
	"strings"

	"github.com/startificial/mayi/internal/domain/resources"
)

const MaxAuthorizationDetailsTypes = 32

type Client struct {
	ApplicationType           string
	Introspection             bool
	AuthenticationVersion     uint64
	AuthMethod                string
	Machine                   bool
	ID, Name                  string
	RedirectURIs, Resources   []string
	AuthorizationDetailsTypes []string
	AccessTokenSeconds        int
	Enabled                   bool
}

// Web clients use exact HTTPS redirects. Machine clients use a disjoint identity
// namespace and confidential authentication, without browser redirects.
func ValidClientID(id string) bool {
	return resources.ValidID(id) || strings.HasPrefix(id, "client:") && resources.ValidID(strings.TrimPrefix(id, "client:"))
}
func (c Client) Valid() bool {
	if c.ApplicationType != "" && c.ApplicationType != "web" && c.ApplicationType != "native" || c.ApplicationType == "native" && (c.Machine || c.Introspection || c.AuthMethod != "" && c.AuthMethod != "none") {
		return false
	}
	if c.Introspection && (c.AuthMethod == "" || c.AuthMethod == "none") {
		return false
	}
	if c.AuthMethod != "" && c.AuthMethod != "none" && c.AuthMethod != "client_secret_basic" && c.AuthMethod != "private_key_jwt" || c.Machine && (!strings.HasPrefix(c.ID, "client:") || c.AuthMethod == "" || c.AuthMethod == "none" || len(c.RedirectURIs) != 0) || !c.Machine && strings.HasPrefix(c.ID, "client:") {
		return false
	}

	if !ValidClientID(c.ID) || !resources.ValidLabel(c.Name) || c.AccessTokenSeconds < 60 || c.AccessTokenSeconds > 900 || (!c.Machine && len(c.RedirectURIs) == 0) || len(c.RedirectURIs) > 16 || len(c.Resources) == 0 || len(c.Resources) > 32 || len(c.AuthorizationDetailsTypes) == 0 || len(c.AuthorizationDetailsTypes) > MaxAuthorizationDetailsTypes {
		return false
	}
	seen := map[string]bool{}
	for _, uri := range c.RedirectURIs {
		if !ValidApplicationRedirect(c.EffectiveApplicationType(), uri) || seen[uri] {
			return false
		}
		seen[uri] = true
	}
	seen = map[string]bool{}
	for _, id := range c.Resources {
		if !resources.ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	seen = map[string]bool{}
	for _, typ := range c.AuthorizationDetailsTypes {
		if !resources.ValidObjectTypeURI(typ) || seen[typ] {
			return false
		}
		seen[typ] = true
	}
	return true
}

// EffectiveApplicationType preserves the registered web profile when omitted.
// Native applications are public even when they use claimed HTTPS callbacks.
func (c Client) EffectiveApplicationType() string {
	if c.ApplicationType == "" {
		return "web"
	}
	return c.ApplicationType
}

// AllowsRedirect applies the loopback port exception only to registered native
// clients. The exact requested URI is subsequently pinned by PAR and the code.
func (c Client) AllowsRedirect(raw string) bool {
	if !c.Valid() || !ValidApplicationRedirect(c.EffectiveApplicationType(), raw) {
		return false
	}
	for _, registered := range c.RedirectURIs {
		if RedirectMatches(c.EffectiveApplicationType(), registered, raw) {
			return true
		}
	}
	return false
}

// AllowsObjectProfile checks the client's registered vocabulary/resource
// ceiling. It establishes neither subject authority nor current object access.
func (c Client) AllowsObjectProfile(resource resources.Resource, profile resources.ObjectProfile) bool {
	s := profile.Snapshot()
	if _, err := resources.NewObjectProfile(s); err != nil || !resources.ValidID(resource.ID) || s.Resource != resource.URI {
		return false
	}
	return c.Valid() && slices.Contains(c.Resources, resource.ID) && slices.Contains(c.AuthorizationDetailsTypes, s.Type)
}
