package admin

import (
	"encoding/json"
	"errors"
	transport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/services/clients"
	"net/http"
	"time"
)

type Credentials struct{ service *clients.Service }

func NewCredentials(service *clients.Service) (*Credentials, error) {
	if service == nil {
		return nil, clients.ErrUnavailable
	}
	return &Credentials{service}, nil
}
func credentialFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, clients.ErrDenied) {
		transport.Error(w, 403, "forbidden")
	} else {
		transport.Error(w, 503, "temporarily_unavailable")
	}
}
func (h *Credentials) Rotate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Overlap int `json:"overlap_seconds"`
	}
	if !transport.Decode(w, r, &input) {
		return
	}
	if input.Overlap < 0 || input.Overlap > 86400 {
		transport.Error(w, 400, "invalid_request")
		return
	}
	actor := middleware.Actor(r)
	secret, err := h.service.Rotate(r.Context(), clients.Operator{Scope: actor.Scope, ID: actor.ID, Permissions: actor.Permissions}, r.PathValue("id"), time.Duration(input.Overlap)*time.Second)
	if err != nil {
		credentialFailure(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	transport.JSON(w, 201, struct {
		Secret string `json:"client_secret"`
	}{secret})
}
func (h *Credentials) Keys(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Keys json.RawMessage `json:"jwks"`
		URI  string          `json:"jwks_uri"`
	}
	if !transport.Decode(w, r, &input) {
		return
	}
	actor := middleware.Actor(r)
	inline := string(input.Keys)
	if inline == "null" {
		inline = ""
	}
	err := h.service.ConfigureKeys(r.Context(), clients.Operator{Scope: actor.Scope, ID: actor.ID, Permissions: actor.Permissions}, r.PathValue("id"), inline, input.URI)
	if err != nil {
		credentialFailure(w, err)
		return
	}
	w.WriteHeader(204)
}
