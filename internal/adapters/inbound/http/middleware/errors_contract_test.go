package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
)

func TestErrorContractCorrelationDoesNotTrustRequestHeaders(t *testing.T) {
	var logs bytes.Buffer
	telemetry := NewTelemetry(slog.New(slog.NewJSONHandler(&logs, nil)))
	handler := telemetry.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httptransport.Error(w, 403, "forbidden")
	}))
	r := httptest.NewRequest(http.MethodGet, "/private-object?token=private-token", nil)
	r.Header.Set("X-Request-ID", "caller-controlled-secret")
	r.Header.Set("Authorization", "Bearer private-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	id := w.Header().Get("X-Request-ID")
	if w.Code != 403 || len(id) != 32 || body["request_id"] != id || !strings.Contains(logs.String(), id) {
		t.Fatal("missing response/log correlation", w.Body.String(), logs.String())
	}
	for _, secret := range []string{"private-token", "caller-controlled-secret", "private-object"} {
		if strings.Contains(w.Body.String()+logs.String(), secret) {
			t.Fatal("request data disclosed")
		}
	}
}
