package clients

import (
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ValidRedirectURI owns the public HTTPS web-client redirect profile. Fixed
// query components are preserved byte-for-byte; fragments and native redirects
// are excluded. Resource-audience policy is intentionally a separate invariant.
func ValidRedirectURI(raw string) bool {
	if len(raw) == 0 || len(raw) > 2048 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\\#") {
		return false
	}
	for _, c := range raw {
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.String() != raw || u.Host != strings.ToLower(u.Host) {
		return false
	}
	// Keep P1's DNS/IPv4 authority profile. Native and IPv6-literal exceptions need
	// their own later capability decision, rather than a resource-rule fallback.
	host := u.Hostname()
	if len(host) > 253 || strings.ContainsAny(host, ":%") || strings.HasSuffix(u.Host, ":") {
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
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	// net/url validates path escapes during Parse; query escapes need an explicit
	// check. No decoding or re-encoding is applied to the stored redirect.
	if _, err := url.QueryUnescape(u.RawQuery); err != nil {
		return false
	}
	// RawQuery is preserved by URL.String without escaping. Require URI query
	// characters here too, so quotes/brackets/control syntax must be encoded.
	for _, c := range u.RawQuery {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~!$&'()*+,;=:@/?%", c) {
			continue
		}
		return false
	}
	return true
}

// ValidAuthorizationRedirect rejects fixed query members reserved for the
// authorization response, so successful/error responses cannot become ambiguous
// or overwrite a client's registered fixed query data.
func ValidAuthorizationRedirect(raw string) bool {
	if !ValidRedirectURI(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	for _, name := range []string{"code", "state", "iss", "error", "error_description", "error_uri"} {
		if _, ok := q[name]; ok {
			return false
		}
	}
	return true
}
