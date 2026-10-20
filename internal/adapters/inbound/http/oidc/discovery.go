// Package oidc provides public issuer/key metadata. P1 does not enable OIDC.
package oidc

import (
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/discovery"
	"net/http"
)

type Handler struct {
	service           *discovery.Service
	scope             grants.Scope
	live, interactive bool
}

func New(service *discovery.Service, scope grants.Scope) (*Handler, error) {
	if service == nil || !scope.Valid() {
		return nil, discovery.ErrUnavailable
	}
	return &Handler{service: service, scope: scope}, nil
}

func NewLive(service *discovery.Service, scope grants.Scope, interactive bool) (*Handler, error) {
	h, err := New(service, scope)
	if err != nil {
		return nil, err
	}
	h.live = true
	h.interactive = interactive
	return h, nil
}

// Metadata is a deliberately marked foundation preview, not a conformant AS or
// OP configuration. Never invent endpoints to satisfy a required metadata field.
func (h *Handler) Metadata(w http.ResponseWriter, r *http.Request) {
	document, err := h.service.Document(r.Context(), h.scope)
	if err != nil {
		httptransport.Error(w, 503, "temporarily_unavailable")
		return
	}
	if h.live {
		issuer := h.scope.Issuer
		value := map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks", "token_endpoint": issuer + "/token", "introspection_endpoint": issuer + "/introspect", "revocation_endpoint": issuer + "/revoke", "grant_types_supported": []string{"client_credentials"}, "response_types_supported": []string{}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "private_key_jwt"}, "token_endpoint_auth_signing_alg_values_supported": []string{"ES256", "PS256", "RS256"}, "mayi_stage": "P2-preview"}
		value["authorization_details_types_supported"] = document.AuthorizationDetailTypes
		value["dpop_signing_alg_values_supported"] = []string{"ES256"}
		if h.interactive {
			value["authorization_endpoint"] = issuer + "/authorize"
			value["pushed_authorization_request_endpoint"] = issuer + "/par"
			value["require_pushed_authorization_requests"] = true
			value["grant_types_supported"] = []string{"authorization_code", "refresh_token", "client_credentials"}
			value["response_types_supported"] = []string{"code"}
			value["response_modes_supported"] = []string{"query"}
			value["code_challenge_methods_supported"] = []string{"S256"}
			value["authorization_response_iss_parameter_supported"] = true
			value["subject_types_supported"] = []string{"public"}
			value["id_token_signing_alg_values_supported"] = []string{"ES256"}
			value["scopes_supported"] = []string{"openid", "offline_access"}
			value["claims_supported"] = []string{"iss", "sub", "aud", "exp", "iat", "nonce", "auth_time"}
			value["claims_parameter_supported"] = false
		}
		httptransport.JSON(w, 200, value)
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
