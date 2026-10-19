// Package egress constrains every untrusted upstream fetch to configured URLs,
// public DNS addresses, bounded responses and a redirect-free transport.
package egress

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/startificial/mayi/internal/adapters/outbound/egress/httpclient"
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
	client, err := httpclient.New(httpclient.Config{URLs: c.URLs, AllowLoopbackHTTP: c.AllowLoopbackHTTP})
	if err != nil {
		return nil, ErrDenied
	}
	allowed := map[string]bool{}
	for _, raw := range c.URLs {
		allowed[raw] = true
	}
	return &Client{http: client, allowed: allowed}, nil
}
func publicIP(ip netip.Addr) bool { return httpclient.PublicIP(ip) }
func safeAnswers(host, port string, ips []netip.Addr, allow bool) bool {
	return httpclient.SafeAnswers(host, port, ips, allow)
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
