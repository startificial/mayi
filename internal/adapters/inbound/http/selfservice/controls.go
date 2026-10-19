package selfservice

import (
	"errors"
	transport "github.com/startificial/mayi/internal/adapters/inbound/http"
	domain "github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authentication"
	"github.com/startificial/mayi/internal/services/grants"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Controls struct {
	sessions *authentication.Sessions
	grants   *grants.Service
	scope    domain.Scope
	origin   string
	cookies  *Handler
}

func NewControls(s *authentication.Sessions, g *grants.Service, scope domain.Scope) (*Controls, error) {
	u, err := url.Parse(scope.Issuer)
	if err != nil || !scope.Valid() || s == nil || g == nil {
		return nil, authentication.ErrUnavailable
	}
	return &Controls{s, g, scope, u.Scheme + "://" + u.Host, &Handler{scope: scope}}, nil
}
func (c *Controls) proof(w http.ResponseWriter, r *http.Request) (authentication.SessionProof, bool) {
	headers(w)
	if r.URL.RawQuery != "" {
		transport.Error(w, 400, "invalid_request")
		return authentication.SessionProof{}, false
	}
	if r.Method == "POST" {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
		if err != nil || len(body) != 0 || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != c.origin {
			transport.Error(w, 400, "invalid_request")
			return authentication.SessionProof{}, false
		}
	}
	session, e1 := c.cookies.cookie(r, "session")
	browser, e2 := c.cookies.cookie(r, "browser")
	if e1 != nil || e2 != nil || !validSecret(session) || !validSecret(browser) {
		transport.Error(w, 400, "invalid_request")
		return authentication.SessionProof{}, false
	}
	return authentication.SessionProof{Scope: c.scope, SessionHash: digest(session), BrowserHash: digest(browser)}, true
}
func controlFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, authentication.ErrDenied) || errors.Is(err, grants.ErrDenied) {
		transport.Error(w, 400, "invalid_request")
	} else {
		transport.Error(w, 503, "temporarily_unavailable")
	}
}
func (c *Controls) Sessions(w http.ResponseWriter, r *http.Request) {
	p, ok := c.proof(w, r)
	if !ok {
		return
	}
	if r.Method == "POST" {
		if err := c.sessions.Revoke(r.Context(), p, r.PathValue("id")); err != nil {
			controlFailure(w, err)
			return
		}
		w.WriteHeader(204)
		return
	}
	result, err := c.sessions.List(r.Context(), p)
	if err != nil {
		controlFailure(w, err)
		return
	}
	type sessionDTO struct {
		Reference string    `json:"reference"`
		Current   bool      `json:"current"`
		Created   time.Time `json:"created_at"`
		LastUsed  time.Time `json:"last_used_at"`
		Expires   time.Time `json:"expires_at"`
	}
	values := make([]sessionDTO, 0, len(result))
	for _, s := range result {
		values = append(values, sessionDTO{s.Reference, s.Current, s.CreatedAt, s.LastUsedAt, s.ExpiresAt})
	}
	transport.JSON(w, 200, values)
}
func (c *Controls) Grants(w http.ResponseWriter, r *http.Request) {
	p, ok := c.proof(w, r)
	if !ok {
		return
	}
	proof := grants.BrowserProof{Scope: p.Scope, SessionHash: p.SessionHash, BrowserHash: p.BrowserHash}
	if r.Method == "POST" {
		if err := c.grants.Revoke(r.Context(), proof, r.PathValue("id")); err != nil {
			controlFailure(w, err)
			return
		}
		w.WriteHeader(204)
		return
	}
	result, err := c.grants.List(r.Context(), proof)
	if err != nil {
		controlFailure(w, err)
		return
	}
	type detail struct {
		Type       string   `json:"type"`
		Locations  []string `json:"locations"`
		Identifier string   `json:"identifier"`
		Actions    []string `json:"actions"`
	}
	type grantDTO struct {
		ID       string    `json:"id"`
		Client   string    `json:"client_id"`
		Resource string    `json:"resource"`
		Revision uint64    `json:"revision"`
		Scopes   []string  `json:"scopes"`
		Details  []detail  `json:"authorization_details"`
		Expires  time.Time `json:"expires_at"`
	}
	values := make([]grantDTO, 0, len(result))
	for _, g := range result {
		v := grantDTO{ID: g.ID, Client: g.ClientID, Resource: g.Resource, Revision: g.Revision, Scopes: g.Scopes, Expires: g.ExpiresAt}
		for _, d := range g.Objects.Snapshot().Details {
			v.Details = append(v.Details, detail{d.Type, []string{g.Resource}, d.Identifier, d.Actions})
		}
		values = append(values, v)
	}
	transport.JSON(w, 200, values)
}

func (c *Controls) Touch(w http.ResponseWriter, r *http.Request) {
	p, ok := c.proof(w, r)
	if !ok {
		return
	}
	if err := c.sessions.Touch(r.Context(), p); err != nil {
		controlFailure(w, err)
		return
	}
	w.WriteHeader(204)
}
