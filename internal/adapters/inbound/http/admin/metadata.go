package admin

import (
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/domain/clients"
	"net/http"
)

type redirectApprovalDTO struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
}
type metadataPolicyDTO struct {
	Version            uint64                `json:"version"`
	Mode               string                `json:"mode"`
	Hosts              []string              `json:"hosts"`
	ApprovedClients    []string              `json:"approved_clients"`
	Resources          []string              `json:"resources"`
	Types              []string              `json:"authorization_details_types"`
	RedirectApprovals  []redirectApprovalDTO `json:"redirect_approvals"`
	MaxClients         int                   `json:"max_clients"`
	AccessTokenSeconds int                   `json:"access_token_seconds"`
}

func (h *Handler) MetadataPolicy(w http.ResponseWriter, r *http.Request) {
	actor := middleware.Actor(r)
	var result clients.MetadataPolicy
	var err error
	if r.Method == http.MethodPut {
		var input metadataPolicyDTO
		if !httptransport.Decode(w, r, &input) {
			return
		}
		p := clients.MetadataPolicy{Version: input.Version, Mode: input.Mode, Hosts: input.Hosts, ApprovedClients: input.ApprovedClients, Resources: input.Resources, AuthorizationDetailsTypes: input.Types, MaxClients: input.MaxClients, AccessTokenSeconds: input.AccessTokenSeconds}
		for _, a := range input.RedirectApprovals {
			p.RedirectApprovals = append(p.RedirectApprovals, clients.RedirectApproval{ClientID: a.ClientID, RedirectURIs: a.RedirectURIs})
		}
		result, err = h.service.SetMetadataPolicy(r.Context(), actor, h.scope, p)
	} else {
		result, err = h.service.MetadataPolicy(r.Context(), actor, h.scope)
	}
	if err != nil {
		failure(w, err)
		return
	}
	wire := metadataPolicyDTO{Version: result.Version, Mode: result.Mode, Hosts: result.Hosts, ApprovedClients: result.ApprovedClients, Resources: result.Resources, Types: result.AuthorizationDetailsTypes, MaxClients: result.MaxClients, AccessTokenSeconds: result.AccessTokenSeconds}
	for _, a := range result.RedirectApprovals {
		wire.RedirectApprovals = append(wire.RedirectApprovals, redirectApprovalDTO{a.ClientID, a.RedirectURIs})
	}
	httptransport.JSON(w, 200, wire)
}
