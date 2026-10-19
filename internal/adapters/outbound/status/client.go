// Package status implements authenticated authoritative token introspection.
package status

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/startificial/mayi/internal/domain/grants"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/resource"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var _ resource.Status = (*Client)(nil)

type Config struct {
	Scope                      grants.Scope
	Endpoint, ClientID, Secret string
}
type Client struct {
	config Config
	http   *http.Client
}

func New(c Config, httpClient *http.Client) (*Client, error) {
	if !c.Scope.Valid() || c.ClientID == "" || c.Secret == "" || httpClient == nil || httpClient.Timeout <= 0 || httpClient.Timeout > 10*time.Second {
		return nil, resource.ErrUnavailable
	}
	return &Client{c, httpClient}, nil
}
func (c *Client) ValidateToken(ctx context.Context, q resource.TokenRequest) (resource.ValidatedToken, error) {
	form := url.Values{"token": {q.Token}, "resource": {q.Resource}}
	if q.Proof != "" {
		form.Set("dpop", q.Proof)
		form.Set("method", q.Method)
		form.Set("url", q.URL)
	}
	r, err := http.NewRequestWithContext(ctx, "POST", c.config.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return resource.ValidatedToken{}, resource.ErrUnavailable
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(c.config.ClientID), url.QueryEscape(c.config.Secret))
	response, err := c.http.Do(r)
	if err != nil {
		return resource.ValidatedToken{}, resource.ErrUnavailable
	}
	defer response.Body.Close()
	media, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || media != "application/json" {
		return resource.ValidatedToken{}, resource.ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128<<10+1))
	if err != nil || len(body) > 128<<10 || response.StatusCode != 200 {
		return resource.ValidatedToken{}, resource.ErrUnavailable
	}
	var wire struct {
		Active        bool   `json:"active"`
		Issuer        string `json:"iss"`
		Tenant        string `json:"tenant_id"`
		Subject       string `json:"sub"`
		Audience      string `json:"aud"`
		ClientID      string `json:"client_id"`
		ID            string `json:"jti"`
		GrantID       string `json:"grant_id"`
		Revision      uint64 `json:"grant_revision"`
		PrincipalType string `json:"principal_type"`
		Scope         string `json:"scope"`
		Issued        int64  `json:"iat"`
		Expires       int64  `json:"exp"`
		Details       []struct {
			Type       string   `json:"type"`
			Locations  []string `json:"locations"`
			Identifier string   `json:"identifier"`
			Actions    []string `json:"actions"`
		} `json:"authorization_details"`
		CNF *struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
		TokenType     string `json:"token_type"`
		ProofVerified bool   `json:"mayi_proof_verified"`
	}
	if !uniqueJSON(body) {
		return resource.ValidatedToken{}, resource.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || d.Decode(&struct{}{}) != io.EOF {
		return resource.ValidatedToken{}, resource.ErrUnavailable
	}
	if !wire.Active {
		return resource.ValidatedToken{}, resource.ErrDenied
	}
	cscope := grants.Scope{TenantID: wire.Tenant, Issuer: wire.Issuer}
	if cscope != c.config.Scope || wire.Audience != q.Resource {
		return resource.ValidatedToken{}, resource.ErrDenied
	}
	var details []grants.ObjectDetail
	for _, d := range wire.Details {
		if len(d.Locations) != 1 || d.Locations[0] != q.Resource {
			return resource.ValidatedToken{}, resource.ErrDenied
		}
		details = append(details, grants.ObjectDetail{Type: d.Type, Identifier: d.Identifier, Actions: d.Actions})
	}
	ceiling, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: cscope, Resource: q.Resource, Details: details})
	if err != nil || len(details) == 0 {
		return resource.ValidatedToken{}, resource.ErrDenied
	}
	claims := domain.AccessClaims{Scope: cscope, ID: wire.ID, GrantID: wire.GrantID, Revision: wire.Revision, Subject: wire.Subject, ClientID: wire.ClientID, PrincipalType: wire.PrincipalType, Resource: wire.Audience, Scopes: strings.Fields(wire.Scope), IssuedAt: time.Unix(wire.Issued, 0), ExpiresAt: time.Unix(wire.Expires, 0), ObjectCeiling: ceiling}
	if wire.CNF != nil {
		if wire.CNF.JKT == "" || wire.TokenType != "DPoP" {
			return resource.ValidatedToken{}, resource.ErrDenied
		}
		claims.BindingThumbprint = wire.CNF.JKT
	} else if wire.TokenType != "Bearer" {
		return resource.ValidatedToken{}, resource.ErrDenied
	}
	return resource.ValidatedToken{Claims: claims, ProofVerified: wire.ProofVerified && q.Proof != ""}, nil
}

// Strict duplicate/depth validation precedes typed decoding of the response.
func uniqueJSON(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 8 {
			return false
		}
		t, err := d.Token()
		if err != nil {
			return false
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			_, isDelimiter := t.(json.Delim)
			return !isDelimiter
		}
	}
	return value(0) && func() bool { _, err := d.Token(); return err == io.EOF }()
}
