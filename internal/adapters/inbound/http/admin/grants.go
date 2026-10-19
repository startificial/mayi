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
