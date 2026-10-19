package admin

import (
	"errors"
	transport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/services/grants"
	"net/http"
)

type GrantControls struct{ service *grants.Service }

func NewGrantControls(service *grants.Service) (*GrantControls, error) {
	if service == nil {
		return nil, grants.ErrUnavailable
	}
	return &GrantControls{service}, nil
}
func (h *GrantControls) Revoke(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Kind      string `json:"kind"`
		Reference string `json:"reference"`
	}
	if !transport.Decode(w, r, &input) {
		return
	}
	actor := middleware.Actor(r)
	err := h.service.AdminRevoke(r.Context(), grants.Operator{Scope: actor.Scope, ID: actor.ID, Permissions: actor.Permissions}, input.Kind, input.Reference)
	if errors.Is(err, grants.ErrDenied) {
		transport.Error(w, 403, "forbidden")
		return
	}
	if err != nil {
		transport.Error(w, 503, "temporarily_unavailable")
		return
	}
	w.WriteHeader(204)
}

func (h *GrantControls) List(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if len(query) > 1 || len(query["after"]) > 1 || len(query) == 1 && !query.Has("after") {
		transport.Error(w, 400, "invalid_request")
		return
	}
	actor := middleware.Actor(r)
	result, err := h.service.AdminList(r.Context(), grants.Operator{Scope: actor.Scope, ID: actor.ID, Permissions: actor.Permissions}, query.Get("after"))
	if errors.Is(err, grants.ErrDenied) {
		transport.Error(w, 403, "forbidden")
		return
	}
	if err != nil {
		transport.Error(w, 503, "temporarily_unavailable")
		return
	}
	type summary struct {
		ID           string   `json:"id"`
		Client       string   `json:"client_id"`
		Subject      string   `json:"subject"`
		Resource     string   `json:"resource"`
		Revision     uint64   `json:"revision"`
		Scopes       []string `json:"scopes"`
		TokensIssued uint64   `json:"tokens_issued"`
	}
	values := make([]summary, 0, len(result))
	for _, g := range result {
		values = append(values, summary{g.ID, g.ClientID, g.Subject, g.Resource, g.Revision, g.Scopes, g.TokensIssued})
	}
	next := ""
	if len(result) == 100 {
		next = result[len(result)-1].ID
	}
	transport.JSON(w, 200, struct {
		Grants []summary `json:"grants"`
		Next   string    `json:"after,omitempty"`
	}{values, next})
}
