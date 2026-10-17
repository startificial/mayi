package app

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/startificial/mayi/internal/domain/grants"
)

var ErrInvalidIssuer = errors.New("issuer requires a canonical HTTPS origin and stable tenant ID")

// NewIssuerScope is used at tenant provisioning. The origin is trusted startup
// configuration, never Host, Forwarded or a user-editable tenant slug.
func NewIssuerScope(origin, tenantID string) (grants.Scope, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != origin || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Hostname(), ".") {
		return grants.Scope{}, ErrInvalidIssuer
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return grants.Scope{}, ErrInvalidIssuer
		}
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return grants.Scope{}, ErrInvalidIssuer
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return grants.Scope{}, ErrInvalidIssuer
				}
			}
		}
	}
	if tenantID == "" || len(tenantID) > 64 || tenantID[0] == '-' || tenantID[len(tenantID)-1] == '-' {
		return grants.Scope{}, ErrInvalidIssuer
	}
	for _, c := range tenantID {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return grants.Scope{}, ErrInvalidIssuer
		}
	}
	return grants.Scope{TenantID: tenantID, Issuer: origin + "/t/" + tenantID}, nil
}
