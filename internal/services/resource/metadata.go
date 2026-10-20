package resource

import (
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"net/url"
	"slices"
	"strings"
)

// Metadata is the public resource-owned capability projection. It never loads
// private registration or ACL data. The operator selects advertised permissions;
// omission does not grant or deny authority, which WithAccess still enforces.
type Metadata struct {
	Resource, Issuer, Name, URL, Path string
	PermissionScopes, DetailTypes     []string
}

type Discovery struct{ metadata Metadata }

func NewDiscovery(issuer, audience, name string, scopes, types []string) (*Discovery, error) {
	if !resources.ValidURI(issuer) || !resources.ValidURI(audience) || !resources.ValidLabel(name) || len(scopes) == 0 || len(scopes) > 128 || !grants.ValidScopes(scopes) || len(types) == 0 || len(types) > 32 {
		return nil, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, typ := range types {
		if !resources.ValidObjectTypeURI(typ) || seen[typ] {
			return nil, ErrUnavailable
		}
		seen[typ] = true
	}
	u, err := url.Parse(audience)
	if err != nil {
		return nil, ErrUnavailable
	}
	path := "/.well-known/oauth-protected-resource" + u.EscapedPath()
	return &Discovery{Metadata{Resource: audience, Issuer: issuer, Name: name, URL: u.Scheme + "://" + u.Host + path, Path: path, PermissionScopes: slices.Clone(scopes), DetailTypes: slices.Clone(types)}}, nil
}

func (d *Discovery) Document() Metadata {
	m := d.metadata
	m.PermissionScopes = slices.Clone(m.PermissionScopes)
	m.DetailTypes = slices.Clone(m.DetailTypes)
	return m
}

// PermissionHint permits only bounded, distinct, publicly advertised permission
// names. It never looks up a protected object's required permissions.
func (d *Discovery) PermissionHint(permissions []string) (string, bool) {
	if len(permissions) > 128 || !grants.ValidScopes(permissions) {
		return "", false
	}
	for _, permission := range permissions {
		if !slices.Contains(d.metadata.PermissionScopes, permission) {
			return "", false
		}
	}
	return strings.Join(permissions, " "), true
}
