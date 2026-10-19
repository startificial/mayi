// Package api forwards only to the configured application's protected API.
package api

import (
	"context"
	"encoding/json"
	"github.com/startificial/mayi/examples/bff/services"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var _ services.API = (*Client)(nil)

type Client struct {
	audience string
	http     *http.Client
}

func New(audience string, httpClient *http.Client) (*Client, error) {
	u, err := url.Parse(audience)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || httpClient == nil || httpClient.Timeout <= 0 || httpClient.Timeout > 10*time.Second {
		return nil, services.ErrAPI
	}
	copy := *httpClient
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{strings.TrimSuffix(audience, "/"), &copy}, nil
}
func (c *Client) ReadObject(ctx context.Context, access, id string) ([]byte, error) {
	if id == "" || len(id) > 256 || access == "" || len(access) > 65536 {
		return nil, services.ErrAPI
	}
	r, err := http.NewRequestWithContext(ctx, "GET", c.audience+"/documents/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, services.ErrAPI
	}
	r.Header.Set("Authorization", "Bearer "+access)
	r.Header.Set("Accept", "application/json")
	response, err := c.http.Do(r)
	if err != nil {
		return nil, services.ErrAPI
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 || response.StatusCode != 200 || !json.Valid(body) {
		return nil, services.ErrAPI
	}
	return body, nil
}
