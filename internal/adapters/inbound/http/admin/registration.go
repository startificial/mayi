package admin

import (
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/domain/clients"
	"net/http"
)

type registrationPolicyDTO struct {
	Version                   uint64   `json:"version"`
	Mode                      string   `json:"mode"`
	Resources                 []string `json:"resources"`
	AuthorizationDetailsTypes []string `json:"authorization_details_types"`
	MaxClients                int      `json:"max_clients"`
	AccessTokenSeconds        int      `json:"access_token_seconds"`
	RequireInitialAccess      bool     `json:"require_initial_access"`
}

func (h *Handler) RegistrationPolicy(w http.ResponseWriter, r *http.Request) {
	actor := middleware.Actor(r)
	var result clients.RegistrationPolicy
	var err error
	if r.Method == http.MethodPut {
		var input registrationPolicyDTO
		if !httptransport.Decode(w, r, &input) {
			return
		}
		result, err = h.service.SetRegistrationPolicy(r.Context(), actor, h.scope, clients.RegistrationPolicy{Version: input.Version, Mode: input.Mode, Resources: input.Resources, AuthorizationDetailsTypes: input.AuthorizationDetailsTypes, MaxClients: input.MaxClients, AccessTokenSeconds: input.AccessTokenSeconds, RequireInitialAccess: input.RequireInitialAccess})
	} else {
		result, err = h.service.RegistrationPolicy(r.Context(), actor, h.scope)
	}
	if err != nil {
		failure(w, err)
		return
	}
	httptransport.JSON(w, 200, registrationPolicyDTO{result.Version, result.Mode, result.Resources, result.AuthorizationDetailsTypes, result.MaxClients, result.AccessTokenSeconds, result.RequireInitialAccess})
}
