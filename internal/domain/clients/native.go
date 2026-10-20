package clients

import (
	"net/url"
	"strconv"
	"strings"
)

// ValidApplicationRedirect selects a registered application's callback policy.
// Private schemes have reverse-DNS syntax; only operator registration establishes
// trust in the claimed publisher. These checks never establish domain ownership.
func ValidApplicationRedirect(applicationType, raw string) bool {
	if applicationType == "" || applicationType == "web" {
		return ValidAuthorizationRedirect(raw)
	}
	if applicationType != "native" {
		return false
	}
	if ValidAuthorizationRedirect(raw) {
		return true
	}
	if len(raw) == 0 || len(raw) > 2048 || strings.ContainsAny(raw, "\\#") {
		return false
	}
	for _, c := range raw {
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.String() != raw || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return false
	}
	if u.Scheme == "http" {
		if !nativeLoopback(u) {
			return false
		}
	} else {
		if u.Host != "" || strings.HasPrefix(u.Path, "//") || raw != u.Scheme+":"+u.EscapedPath()+querySuffix(u) || !strings.Contains(u.Scheme, ".") || !reverseDomainScheme(u.Scheme) {
			return false
		}
	}
	// Reuse the web URI grammar for path/query and reserved response members,
	// without sharing the separate resource-audience policy or normalizing bytes.
	return ValidAuthorizationRedirect("https://callback.example" + u.EscapedPath() + querySuffix(u))
}

func reverseDomainScheme(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
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

func querySuffix(u *url.URL) string {
	if u.ForceQuery || u.RawQuery != "" {
		return "?" + u.RawQuery
	}
	return ""
}

func nativeLoopback(u *url.URL) bool {
	if u.Scheme != "http" || u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	port := u.Port()
	if port == "" {
		return u.Host == "127.0.0.1" || u.Host == "[::1]"
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}

// RedirectMatches compares exact strings except for the port of native HTTP
// loopback callbacks. Host/address family, escaped path and fixed query stay exact.
func RedirectMatches(applicationType, registered, requested string) bool {
	if !ValidApplicationRedirect(applicationType, registered) || !ValidApplicationRedirect(applicationType, requested) {
		return false
	}
	if registered == requested {
		return true
	}
	if applicationType != "native" {
		return false
	}
	a, _ := url.Parse(registered)
	b, _ := url.Parse(requested)
	return nativeLoopback(a) && nativeLoopback(b) && a.Hostname() == b.Hostname() && a.EscapedPath() == b.EscapedPath() && a.RawQuery == b.RawQuery && a.ForceQuery == b.ForceQuery
}
