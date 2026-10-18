// Package egress constrains every untrusted upstream fetch to configured URLs,
// public DNS addresses, bounded responses and a redirect-free transport.
package egress

import (
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/startificial/mayi/internal/services/authentication"
)

var ErrDenied = errors.New("upstream fetch denied")
var _ authentication.UpstreamTransport = (*Client)(nil)

type Config struct {
	URLs              []string
	AllowLoopbackHTTP bool
}
type Client struct {
	http    *http.Client
	allowed map[string]bool
}

func New(c Config) (*Client, error) {
	if len(c.URLs) == 0 || len(c.URLs) > 16 {
		return nil, ErrDenied
	}
	allowed := map[string]bool{}
	for _, raw := range c.URLs {
		u, err := url.Parse(raw)
		if err != nil || len(raw) > 2048 || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Host == "" || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Hostname(), ".") || u.String() != raw || u.Scheme != "https" && !(c.AllowLoopbackHTTP && u.Scheme == "http" && literalLoopback(u.Hostname())) {
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
		if !safeAnswers(host, port, ips, c.AllowLoopbackHTTP) {
			return nil, ErrDenied
		}
		// Dial a validated literal, preserving the original hostname for TLS. No
		// second resolver lookup can rebind it to an internal service.
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return &Client{http: &http.Client{Transport: t, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}, allowed: allowed}, nil
}
func safeAnswers(host, port string, ips []netip.Addr, allowLoopback bool) bool {
	if len(ips) == 0 || len(ips) > 16 {
		return false
	}
	for _, ip := range ips {
		if !publicIP(ip) && !(allowLoopback && literalLoopback(host) && ip.IsLoopback() && port != "443") {
			return false
		}
	}
	return true
}
func literalLoopback(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
func publicIP(ip netip.Addr) bool {
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
func (c *Client) GetJSON(ctx context.Context, raw string) ([]byte, error) {
	return c.fetch(ctx, http.MethodGet, raw, nil, "", "")
}
func (c *Client) PostForm(ctx context.Context, raw string, fields []authentication.FormField, id, secret string) ([]byte, error) {
	form := url.Values{}
	for _, f := range fields {
		form.Add(f.Name, f.Value)
	}
	return c.fetch(ctx, http.MethodPost, raw, strings.NewReader(form.Encode()), id, secret)
}
func (c *Client) fetch(ctx context.Context, method, raw string, body io.Reader, id, secret string) ([]byte, error) {
	if !c.allowed[raw] {
		return nil, ErrDenied
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, body)
	if err != nil {
		return nil, ErrDenied
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if secret != "" {
			req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
		}
	}
	response, err := c.http.Do(req)
	if err != nil {
		return nil, ErrDenied
	}
	defer response.Body.Close()
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || response.StatusCode != 200 {
		return nil, ErrDenied
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return nil, ErrDenied
	}
	return data, nil
}
