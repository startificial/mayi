// Package clients defines registered public web clients and vocabulary ceilings.
package clients

import (
	"slices"

	"github.com/startificial/mayi/internal/domain/resources"
)

const MaxAuthorizationDetailsTypes = 32

type Client struct {
	ID, Name                  string
	RedirectURIs, Resources   []string
	AuthorizationDetailsTypes []string
	AccessTokenSeconds        int
	Enabled                   bool
}

// Mayi currently registers public HTTPS web clients only. Confidential
// credentials, native exceptions and live OAuth endpoints remain pending.
func (c Client) Valid() bool {
	if !resources.ValidID(c.ID) || !resources.ValidLabel(c.Name) || c.AccessTokenSeconds < 60 || c.AccessTokenSeconds > 900 || len(c.RedirectURIs) == 0 || len(c.RedirectURIs) > 16 || len(c.Resources) == 0 || len(c.Resources) > 32 || len(c.AuthorizationDetailsTypes) == 0 || len(c.AuthorizationDetailsTypes) > MaxAuthorizationDetailsTypes {
		return false
	}
	seen := map[string]bool{}
	for _, uri := range c.RedirectURIs {
		if !ValidRedirectURI(uri) || seen[uri] {
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

// AllowsObjectProfile checks the client's registered vocabulary/resource
// ceiling. It establishes neither subject authority nor current object access.
func (c Client) AllowsObjectProfile(resource resources.Resource, profile resources.ObjectProfile) bool {
	s := profile.Snapshot()
	if _, err := resources.NewObjectProfile(s); err != nil || !resources.ValidID(resource.ID) || s.Resource != resource.URI {
		return false
	}
	return c.Valid() && slices.Contains(c.Resources, resource.ID) && slices.Contains(c.AuthorizationDetailsTypes, s.Type)
}
