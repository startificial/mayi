// Package resources defines registered authorization targets.
package resources

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/startificial/mayi/internal/domain/grants"
)

type Scope struct{ Name, Description string }
type Resource struct {
	ID, URI, Name      string
	Scopes             []Scope
	AccessTokenSeconds int
	RequireBinding     bool
}

// ValidURI deliberately supports canonical HTTPS resource origins/paths only
// in P1. Network-aware URL parsing is repeated at the inbound boundary.
func ValidURI(s string) bool {
	if len(s) > 2048 || !strings.HasPrefix(s, "https://") || strings.ContainsAny(s, "?#\\") || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c <= 0x20 || c == 0x7f {
			return false
		}
	}
	authority, _, _ := strings.Cut(strings.TrimPrefix(s, "https://"), "/")
	host, port, hasPort := strings.Cut(authority, ":")
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	if len(host) > 253 || host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func ValidID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}
func ValidLabel(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}
func (r Resource) Valid() bool {
	if !ValidID(r.ID) || !ValidURI(r.URI) || !ValidLabel(r.Name) || r.AccessTokenSeconds < 60 || r.AccessTokenSeconds > 900 || len(r.Scopes) == 0 {
		return false
	}
	names := make([]string, 0, len(r.Scopes))
	for _, scope := range r.Scopes {
		if !ValidLabel(scope.Description) {
			return false
		}
		names = append(names, scope.Name)
	}
	return grants.ValidScopes(names)
}
