// Package httpclient is the shared constrained HTTP transport. It has no
// authentication-service or persistence dependencies and is safe in the SDK graph.
package httpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var ErrDenied = errors.New("upstream fetch denied")

type Config struct {
	URLs              []string
	AllowLoopbackHTTP bool
}
type transport struct {
	base    *http.Transport
	allowed map[string]bool
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.allowed[r.URL.String()] {
		return nil, ErrDenied
	}
	return t.base.RoundTrip(r)
}
func New(c Config) (*http.Client, error) {
	if len(c.URLs) == 0 || len(c.URLs) > 16 {
		return nil, ErrDenied
	}
	allowed := map[string]bool{}
	for _, raw := range c.URLs {
		u, err := url.Parse(raw)
		if err != nil || len(raw) > 2048 || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Host == "" || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Hostname(), ".") || u.String() != raw || u.Scheme != "https" && !(c.AllowLoopbackHTTP && u.Scheme == "http" && LiteralLoopback(u.Hostname())) {
			return nil, ErrDenied
		}
		if u.Port() != "" && u.Port() != "443" && u.Scheme == "https" {
			return nil, ErrDenied
		}
		allowed[raw] = true
	}
	t := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, ErrDenied
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 || len(ips) > 16 {
			return nil, ErrDenied
		}
		if !SafeAnswers(host, port, ips, c.AllowLoopbackHTTP) {
			return nil, ErrDenied
		}
		// Dial a validated literal, preserving the original hostname for TLS. No
		// second resolver lookup can rebind it to an internal service.
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return &http.Client{Transport: &transport{base: t, allowed: allowed}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}, nil
}
func SafeAnswers(host, port string, ips []netip.Addr, allowLoopback bool) bool {
	if len(ips) == 0 || len(ips) > 16 {
		return false
	}
	for _, ip := range ips {
		if !PublicIP(ip) && !(allowLoopback && LiteralLoopback(host) && ip.IsLoopback() && port != "443") {
			return false
		}
	}
	return true
}
func LiteralLoopback(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
func PublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// Additional special-use ranges, including metadata, CGNAT, benchmarking,
	// documentation and translation ranges. Accept IPv6 global allocation only.
	if ip.Is6() {
		return netip.MustParsePrefix("2000::/3").Contains(ip) && !netip.MustParsePrefix("2001::/23").Contains(ip) && !netip.MustParsePrefix("2001:db8::/32").Contains(ip) && !netip.MustParsePrefix("2002::/16").Contains(ip) && !netip.MustParsePrefix("3fff::/20").Contains(ip)
	}
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	return true
}
