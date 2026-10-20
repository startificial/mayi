// Package admin maps bounded management DTOs to service operations.
package admin

import (
	"errors"
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/administration"
	"net/http"
	"net/url"
	"strconv"
)

type Handler struct {
	service *administration.Service
	scope   grants.Scope
}

func New(service *administration.Service, scope grants.Scope) (*Handler, error) {
	if service == nil || !scope.Valid() {
		return nil, administration.ErrInvalid
	}
	return &Handler{service, scope}, nil
}

type policyDTO struct {
	RefreshIdleSeconds     int    `json:"refresh_idle_seconds"`
	RefreshAbsoluteSeconds int    `json:"refresh_absolute_seconds"`
	Version                uint64 `json:"version"`
	MaxAccessTokenSeconds  int    `json:"max_access_token_seconds"`
	MaxGrantSeconds        int    `json:"max_grant_seconds"`
	RequireBinding         bool   `json:"require_binding"`
}
type scopeDTO struct {
	RequiresAdmin bool   `json:"requires_admin"`
	Name          string `json:"name"`
	Description   string `json:"description"`
}
type resourceDTO struct {
	TokenFormat        string     `json:"token_format"`
	ID                 string     `json:"id"`
	URI                string     `json:"uri"`
	Name               string     `json:"name"`
	Scopes             []scopeDTO `json:"scopes"`
	AccessTokenSeconds int        `json:"access_token_seconds"`
	RequireBinding     bool       `json:"require_binding"`
}
type clientDTO struct {
	RequireBinding            bool     `json:"dpop_bound_access_tokens"`
	ApplicationType           string   `json:"application_type"`
	AuthMethod                string   `json:"token_endpoint_auth_method"`
	Machine                   bool     `json:"machine"`
	Introspection             bool     `json:"introspection"`
	ID                        string   `json:"id"`
	Name                      string   `json:"name"`
	RedirectURIs              []string `json:"redirect_uris"`
	Resources                 []string `json:"resources"`
	AccessTokenSeconds        int      `json:"access_token_seconds"`
	Enabled                   bool     `json:"enabled"`
	AuthorizationDetailsTypes []string `json:"authorization_details_types"`
}

func failure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, administration.ErrDenied):
		httptransport.Error(w, 403, "forbidden")
	case errors.Is(err, administration.ErrInvalid):
		httptransport.Error(w, 400, "invalid_request")
	case errors.Is(err, administration.ErrConflict):
		httptransport.Error(w, 409, "conflict")
	case errors.Is(err, administration.ErrNotFound):
		httptransport.Error(w, 404, "not_found")
	default:
		httptransport.Error(w, 503, "temporarily_unavailable")
	}
}
func (h *Handler) Policy(w http.ResponseWriter, r *http.Request) {
	actor := middleware.Actor(r)
	var result policy.Tenant
	var err error
	if r.Method == http.MethodPut {
		var input policyDTO
		if !httptransport.Decode(w, r, &input) {
			return
		}
		result, err = h.service.SetPolicy(r.Context(), actor, h.scope, policy.Tenant{RefreshIdleSeconds: input.RefreshIdleSeconds, RefreshAbsoluteSeconds: input.RefreshAbsoluteSeconds, Version: input.Version, MaxAccessTokenSeconds: input.MaxAccessTokenSeconds, MaxGrantSeconds: input.MaxGrantSeconds, RequireBinding: input.RequireBinding})
	} else {
		result, err = h.service.Policy(r.Context(), actor, h.scope)
	}
	if err != nil {
		failure(w, err)
		return
	}
	httptransport.JSON(w, 200, policyDTO{Version: result.Version, MaxAccessTokenSeconds: result.MaxAccessTokenSeconds, MaxGrantSeconds: result.MaxGrantSeconds, RequireBinding: result.RequireBinding, RefreshIdleSeconds: result.RefreshIdle(), RefreshAbsoluteSeconds: result.RefreshAbsolute()})
}
func validURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.String() == raw
}
func (h *Handler) CreateResource(w http.ResponseWriter, r *http.Request) {
	var input resourceDTO
	if !httptransport.Decode(w, r, &input) {
		return
	}
	if !validURL(input.URI) {
		failure(w, administration.ErrInvalid)
		return
	}
	value := resources.Resource{TokenFormat: input.TokenFormat, ID: input.ID, URI: input.URI, Name: input.Name, AccessTokenSeconds: input.AccessTokenSeconds, RequireBinding: input.RequireBinding}
	for _, scope := range input.Scopes {
		value.Scopes = append(value.Scopes, resources.Scope{Name: scope.Name, Description: scope.Description, RequiresAdmin: scope.RequiresAdmin})
	}
	if err := h.service.CreateResource(r.Context(), middleware.Actor(r), h.scope, value); err != nil {
		failure(w, err)
		return
	}
	httptransport.JSON(w, 201, input)
}
func (h *Handler) Resource(w http.ResponseWriter, r *http.Request) {
	value, err := h.service.Resource(r.Context(), middleware.Actor(r), h.scope, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	result := resourceDTO{TokenFormat: value.AccessTokenFormat(), ID: value.ID, URI: value.URI, Name: value.Name, AccessTokenSeconds: value.AccessTokenSeconds, RequireBinding: value.RequireBinding}
	for _, scope := range value.Scopes {
		result.Scopes = append(result.Scopes, scopeDTO{Name: scope.Name, Description: scope.Description, RequiresAdmin: scope.RequiresAdmin})
	}
	httptransport.JSON(w, 200, result)
}
func (h *Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	var input clientDTO
	if !httptransport.Decode(w, r, &input) {
		return
	}
	for _, uri := range input.RedirectURIs {
		if !clients.ValidApplicationRedirect(input.ApplicationType, uri) {
			failure(w, administration.ErrInvalid)
			return
		}
	}
	value := clients.Client{RequireBinding: input.RequireBinding, ApplicationType: input.ApplicationType, ID: input.ID, Name: input.Name, RedirectURIs: input.RedirectURIs, Resources: input.Resources, AccessTokenSeconds: input.AccessTokenSeconds, Enabled: input.Enabled, AuthorizationDetailsTypes: input.AuthorizationDetailsTypes, AuthMethod: input.AuthMethod, Machine: input.Machine, Introspection: input.Introspection}
	if err := h.service.CreateClient(r.Context(), middleware.Actor(r), h.scope, value); err != nil {
		failure(w, err)
		return
	}
	httptransport.JSON(w, 201, input)
}
func (h *Handler) Client(w http.ResponseWriter, r *http.Request) {
	value, err := h.service.Client(r.Context(), middleware.Actor(r), h.scope, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	httptransport.JSON(w, 200, clientDTO{RequireBinding: value.RequireBinding, ApplicationType: value.EffectiveApplicationType(), ID: value.ID, Name: value.Name, RedirectURIs: value.RedirectURIs, Resources: value.Resources, AccessTokenSeconds: value.AccessTokenSeconds, Enabled: value.Enabled, AuthorizationDetailsTypes: value.AuthorizationDetailsTypes, AuthMethod: value.AuthMethod, Machine: value.Machine, Introspection: value.Introspection})
}
func (h *Handler) PublishKey(w http.ResponseWriter, r *http.Request) {
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		failure(w, administration.ErrInvalid)
		return
	}
	if err := h.service.PublishKey(r.Context(), middleware.Actor(r), h.scope, version); err != nil {
		failure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h *Handler) ActivateKey(w http.ResponseWriter, r *http.Request) {
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		failure(w, administration.ErrInvalid)
		return
	}
	if err := h.service.ActivateKey(r.Context(), middleware.Actor(r), h.scope, version); err != nil {
		failure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
