package tokens

import (
	"net/url"
	"strings"
)

// ProofTarget compares public HTTPS targets without query components. Request
// targets may have a query; a proof's htu may not. Escaped paths stay exact.
// Configured public targets, never forwarded headers, establish the authority.
func ProofTarget(raw string, proof bool) (string, bool) {
	if len(raw) == 0 || len(raw) > 2048 || strings.ContainsAny(raw, "\\#") {
		return "", false
	}
	for _, c := range raw {
		if c <= 0x20 || c >= 0x7f {
			return "", false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || proof && (u.RawQuery != "" || u.ForceQuery) {
		return "", false
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return "", false
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return "", false
		}
	}
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Host)
	u.RawQuery = ""
	u.ForceQuery = false
	if u.Port() == "443" {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), true
}

func ValidProofNonce(nonce string) bool {
	if len(nonce) < 43 || len(nonce) > 128 {
		return false
	}
	for _, c := range nonce {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
