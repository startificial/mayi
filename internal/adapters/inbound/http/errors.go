package http

import "net/http"

type errorDefinition struct {
	code    string
	status  int
	message string
}

// Keep fixed public descriptions here, never in service errors. The contract
// tests require the developer catalog to describe every definition exactly.
func errorDefinitions() []errorDefinition {
	return []errorDefinition{
		{"invalid_content_type", 415, "Use application/json for this request."},
		{"invalid_request", 400, "The request is malformed or contains unsupported values."},
		{"invalid_token", 401, "Authentication is required or the credential is invalid."},
		{"forbidden", 403, "This operation is not permitted."},
		{"conflict", 409, "The operation conflicts with the current state."},
		{"not_found", 404, "The requested resource is unavailable."},
		{"not_ready", 503, "The service is not ready."},
		{"temporarily_unavailable", 503, "The service is temporarily unavailable."},
		{"internal_error", 500, "The request could not be completed."},
	}
}

// Error writes the local JSON error contract. OAuth protocol responses and
// resource challenges retain their endpoint-specific contracts in their adapters.
// Unknown codes and mismatched statuses are programming errors; fail safely
// instead of reflecting an arbitrary string or accidentally returning success.
func Error(w http.ResponseWriter, status int, code string) {
	selected := errorDefinition{"internal_error", http.StatusInternalServerError, "The request could not be completed."}
	for _, definition := range errorDefinitions() {
		if definition.code == code && definition.status == status {
			selected = definition
			break
		}
	}
	requestID := ""
	ids := w.Header().Values("X-Request-ID")
	if len(ids) == 1 && validRequestID(ids[0]) {
		requestID = ids[0]
	} else {
		w.Header().Del("X-Request-ID")
	}
	JSON(w, selected.status, struct {
		Error     string `json:"error"`
		Message   string `json:"message"`
		RequestID string `json:"request_id,omitempty"`
	}{selected.code, selected.message, requestID})
}

func validRequestID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
