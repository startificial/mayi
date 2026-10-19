package selfservice

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/startificial/mayi/internal/services/authentication"
	"github.com/startificial/mayi/internal/services/authorization"
)

func TestErrorContractBrowserKeepsDenialsGeneric(t *testing.T) {
	for _, cause := range []error{authentication.ErrDenied, authorization.ErrDenied, authorization.ErrInvalid} {
		w := httptest.NewRecorder()
		(&Handler{}).failure(w, fmt.Errorf("private-object-123: %w", cause))
		if w.Code != 400 || strings.TrimSpace(w.Body.String()) != `{"error":"invalid_request","message":"The request is malformed or contains unsupported values."}` || w.Header().Get("Location") != "" {
			t.Fatal("browser denial disclosed state or redirected", w.Code, w.Body.String())
		}
	}
	for _, cause := range []error{authentication.ErrUnavailable, authorization.ErrUnavailable} {
		w := httptest.NewRecorder()
		(&Handler{}).failure(w, fmt.Errorf("private-upstream-body: %w", cause))
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if w.Code != 503 || body["error"] != "temporarily_unavailable" || strings.Contains(w.Body.String(), "private-upstream-body") || w.Header().Get("Location") != "" {
			t.Fatal("browser dependency cause disclosed or redirected", w.Code, w.Body.String())
		}
	}
}
