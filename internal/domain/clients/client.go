// Package clients defines the P1 pre-registered public web-client model.
package clients

import "github.com/startificial/mayi/internal/domain/resources"

type Client struct {
	ID, Name                string
	RedirectURIs, Resources []string
	AccessTokenSeconds      int
	Enabled                 bool
}

// P1 registers public HTTPS web clients only. Authentication, confidential
// credentials, native exceptions and the OAuth endpoints arrive in later phases.
func (c Client) Valid() bool {
	if !resources.ValidID(c.ID) || !resources.ValidLabel(c.Name) || c.AccessTokenSeconds < 60 || c.AccessTokenSeconds > 900 || len(c.RedirectURIs) == 0 || len(c.RedirectURIs) > 16 || len(c.Resources) == 0 || len(c.Resources) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, uri := range c.RedirectURIs {
		if !resources.ValidURI(uri) || seen[uri] {
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
	return true
}
