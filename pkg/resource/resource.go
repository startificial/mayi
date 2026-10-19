// Package resource enforces Mayi access authority and resource-owned current
// permission before an application reads or mutates a protected object.
package resource

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/adapters/outbound/egress/httpclient"
	"github.com/startificial/mayi/internal/adapters/outbound/status"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	service "github.com/startificial/mayi/internal/services/resource"
	"net/http"
	"strings"
	"time"
)

var ErrDenied = errors.New("resource access denied")
var ErrUnavailable = errors.New("resource authority unavailable")

type Profile struct {
	Type    string
	Actions []Action
}
type Action struct{ Name, Description string }
type Config struct {
	Tenant, Issuer, Audience, IntrospectionEndpoint, ClientID, ClientSecret string
	Profiles                                                                []Profile
	AllowInsecureLoopback                                                   bool
}
type Request struct{ Type, Identifier, Action, Permission, Proof, Method, URL string }
type Principal struct {
	Tenant, Issuer, Subject, ClientID, PrincipalType, GrantID string
	Revision                                                  uint64
	Scopes                                                    []string
}

// PermissionGuard must serialize current permission changes with the callback's
// protected operation. It must authorize before loading payloads and invoke fn
// once synchronously. A callback may use the supplied context for resource-owned
// transaction enlistment. Mayi's SDK neither queries nor owns application ACLs.
type PermissionGuard interface {
	WithPermission(context.Context, Principal, Request, func(context.Context) error) error
}
type Client struct{ service *service.Service }
type clock struct{}

func (clock) Now() time.Time { return time.Now() }
func New(c Config, guard PermissionGuard) (*Client, error) {
	if guard == nil {
		return nil, ErrUnavailable
	}
	scope := grants.Scope{TenantID: c.Tenant, Issuer: c.Issuer}
	var profiles []resources.ObjectProfile
	for _, p := range c.Profiles {
		spec := resources.ObjectProfileSpec{Scope: scope, Resource: c.Audience, Type: p.Type, Semantics: resources.ObjectActionsV1}
		for _, a := range p.Actions {
			spec.Actions = append(spec.Actions, resources.ObjectAction{Name: a.Name, Description: a.Description})
		}
		value, err := resources.NewObjectProfile(spec)
		if err != nil {
			return nil, ErrUnavailable
		}
		profiles = append(profiles, value)
	}
	transport, err := httpclient.New(httpclient.Config{URLs: []string{c.IntrospectionEndpoint}, AllowLoopbackHTTP: c.AllowInsecureLoopback})
	if err != nil {
		return nil, ErrUnavailable
	}
	remote, err := status.New(status.Config{Scope: scope, Endpoint: c.IntrospectionEndpoint, ClientID: c.ClientID, Secret: c.ClientSecret}, transport)
	if err != nil {
		return nil, ErrUnavailable
	}
	bridge := status.NewPermissionBridge(func(ctx context.Context, d service.Decision, fn func(context.Context) error) error {
		return guard.WithPermission(ctx, principal(d), request(d.Request), fn)
	})
	validator, err := service.New(remote, bridge, clock{}, scope, c.Audience, profiles)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Client{validator}, nil
}
func principal(d service.Decision) Principal {
	c := d.Claims
	return Principal{Tenant: c.Scope.TenantID, Issuer: c.Scope.Issuer, Subject: c.Subject, ClientID: c.ClientID, PrincipalType: c.PrincipalType, GrantID: c.GrantID, Revision: c.Revision, Scopes: append([]string(nil), c.Scopes...)}
}
func request(r service.Request) Request {
	return Request{r.Type, r.Identifier, r.Action, r.Permission, r.Proof, r.Method, r.URL}
}
func (c *Client) WithAccess(ctx context.Context, token string, r Request, fn func(context.Context, Principal) error) error {
	if c == nil || c.service == nil || fn == nil {
		return ErrDenied
	}
	err := c.service.WithAccess(ctx, token, service.Request{Type: r.Type, Identifier: r.Identifier, Action: r.Action, Permission: r.Permission, Proof: r.Proof, Method: r.Method, URL: r.URL}, func(ctx context.Context, d service.Decision) error { return fn(ctx, principal(d)) })
	if errors.Is(err, service.ErrDenied) {
		return ErrDenied
	}
	if errors.Is(err, service.ErrUnavailable) {
		if ctx.Err() != nil {
			return errors.Join(ErrUnavailable, ctx.Err())
		}
		return ErrUnavailable
	}
	return err
}

// HeaderToken is the sole supported credential location. Resource handlers must
// reject query/body access-token parameters too, before invoking their service.
func HeaderToken(r *http.Request) (string, error) {
	if r == nil || r.URL.Query().Has("access_token") || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("DPoP")) > 1 {
		return "", ErrDenied
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || token == "" || len(token) > 65536 || strings.ContainsAny(token, " \r\n\t") || scheme != "Bearer" && scheme != "DPoP" || scheme == "DPoP" && r.Header.Get("DPoP") == "" || scheme == "Bearer" && r.Header.Get("DPoP") != "" {
		return "", ErrDenied
	}
	return token, nil
}
