package admin

import (
	"encoding/json"
	"errors"
	transport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
	"net/http"
)

type MachinePolicies struct {
	service *tokens.MachinePolicies
	scope   grants.Scope
}

func NewMachinePolicies(service *tokens.MachinePolicies, scope grants.Scope) (*MachinePolicies, error) {
	if service == nil || !scope.Valid() {
		return nil, tokens.ErrUnavailable
	}
	return &MachinePolicies{service, scope}, nil
}
func (h *MachinePolicies) Configure(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Resource string          `json:"resource"`
		Scopes   []string        `json:"scopes"`
		Details  json.RawMessage `json:"authorization_details"`
	}
	if !transport.Decode(w, r, &input) {
		return
	}
	command := tokens.MachineAuthorization{ClientID: r.PathValue("id"), Resource: input.Resource, Scopes: input.Scopes}
	remove := r.Method == http.MethodDelete
	if !remove {
		ceiling, err := oauth.DecodeObjectRequest(string(input.Details), h.scope, input.Resource)
		if err != nil {
			transport.Error(w, 400, "invalid_request")
			return
		}
		command.Objects = ceiling
	}
	actor := middleware.Actor(r)
	if err := h.service.Configure(r.Context(), tokens.MachineOperator{Scope: actor.Scope, ID: actor.ID, Permissions: actor.Permissions}, command, remove); err != nil {
		if errors.Is(err, tokens.ErrMachinePolicyDenied) {
			transport.Error(w, 403, "forbidden")
		} else if errors.Is(err, tokens.ErrInvalidCredential) {
			transport.Error(w, 400, "invalid_request")
		} else {
			transport.Error(w, 503, "temporarily_unavailable")
		}
		return
	}
	w.WriteHeader(204)
}
