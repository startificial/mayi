package resource

import (
	"encoding/json"
	"errors"
	service "github.com/startificial/mayi/internal/services/resource"
	"net/http"
)

// MetadataConfig is trusted resource deployment configuration, never caller
// input. Advertise only public permissions and types enforced by this API.
// Each audience has its own document, including APIs hosted on the same origin.
type MetadataConfig struct {
	Issuer, Audience, Name                     string
	PermissionScopes, AuthorizationDetailTypes []string
}

type MetadataHandler struct{ discovery *service.Discovery }

func NewMetadata(c MetadataConfig) (*MetadataHandler, error) {
	discovery, err := service.NewDiscovery(c.Issuer, c.Audience, c.Name, c.PermissionScopes, c.AuthorizationDetailTypes)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &MetadataHandler{discovery}, nil
}

// MetadataURL never uses a request Host or forwarding header.
func (h *MetadataHandler) MetadataURL() string { return h.discovery.Document().URL }

// MetadataPath retains the audience's escaped path exactly, including a trailing
// slash. Mount this handler on that exact path in the resource's own listener.
func (h *MetadataHandler) MetadataPath() string { return h.discovery.Document().Path }

func (h *MetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	m := h.discovery.Document()
	if r.URL.EscapedPath() != m.Path || r.URL.RawQuery != "" || r.URL.ForceQuery {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		Name                 string   `json:"resource_name"`
		Scopes               []string `json:"scopes_supported"`
		Methods              []string `json:"bearer_methods_supported"`
		Types                []string `json:"authorization_details_types_supported"`
	}{m.Resource, []string{m.Issuer}, m.Name, m.PermissionScopes, []string{"header"}, m.DetailTypes})
}

// WriteChallenge maps only SDK failures, never application callback errors.
// Pass nil for missing authentication (no OAuth error). Supply permission names
// only for ErrInsufficientScope; they must be public configured permissions.
// Object-policy denials stay generic and do not disclose protected existence.
func (h *MetadataHandler) WriteChallenge(w http.ResponseWriter, err error, permissions ...string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	m := h.discovery.Document()
	status, code := http.StatusUnauthorized, ""
	switch {
	case err == nil || errors.Is(err, ErrMissingCredential):
	case errors.Is(err, ErrUnavailable):
		status, code = http.StatusServiceUnavailable, "temporarily_unavailable"
	case errors.Is(err, ErrInvalidRequest):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, ErrInsufficientScope):
		status, code = http.StatusForbidden, "insufficient_scope"
	case errors.Is(err, ErrDenied):
		code = "invalid_token"
	default:
		status, code = http.StatusInternalServerError, "server_error"
	}
	// Scope is a public recovery hint, not an echo of user input or object ACLs.
	hint, valid := h.discovery.PermissionHint(permissions)
	if !valid || len(permissions) != 0 && status != http.StatusForbidden {
		status, code = http.StatusInternalServerError, "server_error"
	}
	if status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden {
		challenge := "Bearer resource_metadata=\"" + m.URL + "\""
		if code != "" {
			challenge += ", error=\"" + code + "\""
		}
		if hint != "" {
			challenge += ", scope=\"" + hint + "\""
		}
		w.Header().Set("WWW-Authenticate", challenge)
	}
	w.WriteHeader(status)
	if code != "" {
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{code})
	}
}
