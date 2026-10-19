package admin

import (
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/adapters/inbound/http/middleware"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/administration"
	"net/http"
	"net/url"
)

type objectProfileDTO struct {
	Resource  string            `json:"resource"`
	Type      string            `json:"type"`
	Semantics string            `json:"semantics"`
	Actions   []objectActionDTO `json:"actions"`
}

type objectActionDTO struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *Handler) RegisterObjectProfile(w http.ResponseWriter, r *http.Request) {
	var input objectProfileDTO
	if !httptransport.Decode(w, r, &input) {
		return
	}
	if !validURL(input.Resource) || !validURL(input.Type) {
		failure(w, administration.ErrInvalid)
		return
	}
	spec := resources.ObjectProfileSpec{Scope: h.scope, Resource: input.Resource, Type: input.Type, Semantics: input.Semantics}
	for _, action := range input.Actions {
		spec.Actions = append(spec.Actions, resources.ObjectAction{Name: action.Name, Description: action.Description})
	}
	if err := h.service.RegisterObjectProfile(r.Context(), middleware.Actor(r), h.scope, r.PathValue("id"), spec); err != nil {
		failure(w, err)
		return
	}
	httptransport.JSON(w, http.StatusCreated, input)
}

func (h *Handler) ObjectProfile(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["type"]) != 1 || !validURL(query.Get("type")) {
		failure(w, administration.ErrInvalid)
		return
	}
	profile, err := h.service.ObjectProfile(r.Context(), middleware.Actor(r), h.scope, r.PathValue("id"), query.Get("type"))
	if err != nil {
		failure(w, err)
		return
	}
	s := profile.Snapshot()
	result := objectProfileDTO{Resource: s.Resource, Type: s.Type, Semantics: s.Semantics}
	for _, action := range s.Actions {
		result.Actions = append(result.Actions, objectActionDTO{Name: action.Name, Description: action.Description})
	}
	httptransport.JSON(w, http.StatusOK, result)
}
