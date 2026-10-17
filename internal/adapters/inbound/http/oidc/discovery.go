// Package oidc provides public issuer/key metadata. P1 does not enable OIDC.
package oidc

import (
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/discovery"
	"net/http"
)

type Handler struct {
	service *discovery.Service
	scope   grants.Scope
}

func New(service *discovery.Service, scope grants.Scope) (*Handler, error) {
	if service == nil || !scope.Valid() {
		return nil, discovery.ErrUnavailable
	}
	return &Handler{service, scope}, nil
}

// Metadata is a deliberately marked foundation preview, not a conformant AS or
// OP configuration. Never invent endpoints to satisfy a required metadata field.
func (h *Handler) Metadata(w http.ResponseWriter, r *http.Request) {
	if _, err := h.service.Document(r.Context(), h.scope); err != nil {
		httptransport.Error(w, 503, "temporarily_unavailable")
		return
	}
	httptransport.JSON(w, 200, struct {
		Issuer        string   `json:"issuer"`
		JWKSURI       string   `json:"jwks_uri"`
		GrantTypes    []string `json:"grant_types_supported"`
		ResponseTypes []string `json:"response_types_supported"`
		Scopes        []string `json:"scopes_supported"`
		Stage         string   `json:"mayi_stage"`
	}{h.scope.Issuer, h.scope.Issuer + "/jwks", []string{}, []string{}, []string{}, "P1-foundation"})
}
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	doc, err := h.service.Document(r.Context(), h.scope)
	if err != nil {
		httptransport.Error(w, 503, "temporarily_unavailable")
		return
	}
	type key struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		ID  string `json:"kid"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	keys := make([]key, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		keys = append(keys, key{"EC", "P-256", "sig", "ES256", k.ID, k.X, k.Y})
	}
	httptransport.JSON(w, 200, struct {
		Keys []key `json:"keys"`
	}{keys})
}
