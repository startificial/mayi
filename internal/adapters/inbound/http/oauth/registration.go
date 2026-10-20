package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"
)

type RegistrationHandler struct {
	service *administration.Registration
	scope   grants.Scope
}

func NewRegistration(service *administration.Registration, scope grants.Scope) (*RegistrationHandler, error) {
	if service == nil || !scope.Valid() {
		return nil, administration.ErrInvalid
	}
	return &RegistrationHandler{service, scope}, nil
}

type registrationDTO struct {
	ClientID                  string   `json:"client_id,omitempty"`
	Name                      string   `json:"client_name"`
	ApplicationType           string   `json:"application_type"`
	RedirectURIs              []string `json:"redirect_uris"`
	AuthMethod                string   `json:"token_endpoint_auth_method"`
	GrantTypes                []string `json:"grant_types"`
	ResponseTypes             []string `json:"response_types"`
	RequireBinding            bool     `json:"dpop_bound_access_tokens"`
	Resources                 []string `json:"mayi_resource_ids"`
	AuthorizationDetailsTypes []string `json:"authorization_details_types"`
}

// Decode exact-case, unique top-level members; the admitted profile has only
// scalar/array values. Unknown metadata is ignored per RFC 7591, but known
// unsupported security capabilities are explicitly refused, never activated.
func registrationInput(w http.ResponseWriter, r *http.Request) (registrationDTO, bool) {
	var result registrationDTO
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return result, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	body, err := io.ReadAll(r.Body)
	if err != nil || !utf8.Valid(body) {
		return result, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return result, false
	}
	seen := map[string]bool{}
	fields := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return result, false
		}
		k, ok := t.(string)
		if !ok || seen[strings.ToLower(k)] {
			return result, false
		}
		seen[strings.ToLower(k)] = true
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return result, false
		}
		switch k {
		case "client_name", "application_type", "redirect_uris", "token_endpoint_auth_method", "grant_types", "response_types", "dpop_bound_access_tokens", "mayi_resource_ids", "authorization_details_types":
			fields[k] = v
		case "client_id", "client_secret", "jwks", "jwks_uri", "software_statement", "scope", "sector_identifier_uri", "request_uris":
			return result, false
		default:
			if slices.Contains([]string{"client_name", "application_type", "redirect_uris", "token_endpoint_auth_method", "grant_types", "response_types", "dpop_bound_access_tokens", "mayi_resource_ids", "authorization_details_types"}, strings.ToLower(k)) {
				return result, false
			}
		}
	}
	if _, err = d.Token(); err != nil || d.Decode(&struct{}{}) != io.EOF {
		return result, false
	}
	b, err := json.Marshal(fields)
	if err != nil || json.Unmarshal(b, &result) != nil {
		return result, false
	}
	// This explicit bounded profile avoids silently selecting confidential
	// authentication or adding a grant type the client did not request.
	if result.AuthMethod != "none" || len(result.GrantTypes) != 2 || !slices.Contains(result.GrantTypes, "authorization_code") || !slices.Contains(result.GrantTypes, "refresh_token") {
		return result, false
	}
	if result.ResponseTypes == nil {
		result.ResponseTypes = []string{"code"}
	}
	if !slices.Equal(result.ResponseTypes, []string{"code"}) {
		return result, false
	}
	if result.ApplicationType == "" {
		result.ApplicationType = "web"
	}
	if result.Name == "" {
		result.Name = "Unverified application"
	}
	result.RequireBinding = true
	return result, true
}

func registrationError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Pragma", "no-cache")
	httptransport.JSON(w, status, struct {
		Error string `json:"error"`
	}{code})
}

func (h *RegistrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(405)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Origin") != "" {
		registrationError(w, 400, "invalid_client_metadata")
		return
	}
	access := ""
	values := r.Header.Values("Authorization")
	if len(values) > 0 {
		if len(values) != 1 || len(values[0]) != 50 || !strings.EqualFold(values[0][:7], "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mayi-registration"`)
			registrationError(w, 401, "invalid_token")
			return
		}
		access = values[0][7:]
	}
	input, ok := registrationInput(w, r)
	if !ok {
		registrationError(w, 400, "invalid_client_metadata")
		return
	}
	for _, uri := range input.RedirectURIs {
		if !clients.ValidApplicationRedirect(input.ApplicationType, uri) {
			registrationError(w, 400, "invalid_redirect_uri")
			return
		}
	}
	c, err := h.service.Register(r.Context(), h.scope, access, clients.PublicRegistration{Name: input.Name, ApplicationType: input.ApplicationType, RedirectURIs: input.RedirectURIs, Resources: input.Resources, AuthorizationDetailsTypes: input.AuthorizationDetailsTypes})
	if err != nil {
		switch {
		case errors.Is(err, administration.ErrInitialAccess):
			w.Header().Set("WWW-Authenticate", `Bearer realm="mayi-registration"`)
			registrationError(w, 401, "invalid_token")
		case errors.Is(err, administration.ErrDenied), errors.Is(err, administration.ErrRegistrationQuota):
			registrationError(w, 403, "invalid_client_metadata")
		case errors.Is(err, administration.ErrRegistrationLimited):
			w.Header().Set("Retry-After", "60")
			registrationError(w, 429, "temporarily_unavailable")
		case errors.Is(err, administration.ErrInvalid), errors.Is(err, administration.ErrNotFound), errors.Is(err, administration.ErrConflict):
			registrationError(w, 400, "invalid_client_metadata")
		default:
			registrationError(w, 503, "temporarily_unavailable")
		}
		return
	}
	input.ClientID = c.ID
	input.Name = c.Name
	input.RedirectURIs = c.RedirectURIs
	input.ApplicationType = c.EffectiveApplicationType()
	w.Header().Set("Pragma", "no-cache")
	httptransport.JSON(w, 201, input)
}
