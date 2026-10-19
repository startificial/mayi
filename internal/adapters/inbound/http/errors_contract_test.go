package http

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestErrorContractCatalog(t *testing.T) {
	data, err := os.ReadFile("../../../../docs/error-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Version int    `json:"version"`
		Surface string `json:"surface"`
		Errors  []struct {
			Code     string `json:"code"`
			Status   int    `json:"status"`
			Message  string `json:"message"`
			Recovery string `json:"recovery"`
			Retry    string `json:"retry"`
		} `json:"errors"`
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err := d.Decode(&catalog); err != nil {
		t.Fatal(err)
	}
	if d.Decode(&struct{}{}) != io.EOF || catalog.Version != 1 || catalog.Surface != "local-json" || len(catalog.Errors) != len(errorDefinitions()) {
		t.Fatal("invalid or incomplete error catalog")
	}
	guide, err := os.ReadFile("../../../../docs/error-handling.md")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range catalog.Errors {
		if seen[entry.Code] || entry.Code == "" || strings.TrimSpace(entry.Recovery) == "" || (entry.Retry != "after-correction" && entry.Retry != "conditional") || !strings.Contains(string(guide), "\n### "+entry.Code+"\n") {
			t.Fatalf("duplicate, incomplete or undocumented entry %q", entry.Code)
		}
		seen[entry.Code] = true
		found := false
		for _, definition := range errorDefinitions() {
			if entry.Code == definition.code && entry.Status == definition.status && entry.Message == definition.message {
				found = true
			}
		}
		if !found {
			t.Fatalf("catalog/transport drift for %q", entry.Code)
		}
	}
}

func TestErrorContractEnvelope(t *testing.T) {
	const requestID = "0123456789abcdef0123456789abcdef"
	for _, definition := range errorDefinitions() {
		t.Run(definition.code, func(t *testing.T) {
			w := httptest.NewRecorder()
			w.Header().Set("X-Request-ID", requestID)
			w.Header().Set("WWW-Authenticate", `Bearer realm="mayi-admin"`)
			Error(w, definition.status, definition.code)
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != definition.status || len(body) != 3 || body["error"] != definition.code || body["message"] != definition.message || body["request_id"] != requestID {
				t.Fatalf("incorrect response: %d %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Request-ID") != requestID || w.Header().Get("WWW-Authenticate") != `Bearer realm="mayi-admin"` {
				t.Fatal("missing or overwritten contract headers", w.Header())
			}
		})
	}
}

func TestErrorContractUnknownMappingsNeverReflectInput(t *testing.T) {
	for _, input := range []struct {
		status int
		code   string
	}{
		{200, "invalid_request"}, {401, "secret-token SQL error"}, {400, "unknown_code"}, {503, "invalid_request"},
	} {
		w := httptest.NewRecorder()
		Error(w, input.status, input.code)
		if w.Code != http.StatusInternalServerError || strings.TrimSpace(w.Body.String()) != `{"error":"internal_error","message":"The request could not be completed."}` {
			t.Fatalf("unsafe fallback: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestErrorContractRequestIDIsBoundedAndOptional(t *testing.T) {
	for _, ids := range [][]string{nil, {"secret-token"}, {strings.Repeat("a", 33)}, {strings.Repeat("A", 32)}, {strings.Repeat("a", 32), strings.Repeat("b", 32)}} {
		w := httptest.NewRecorder()
		for _, id := range ids {
			w.Header().Add("X-Request-ID", id)
		}
		Error(w, 400, "invalid_request")
		if strings.Contains(w.Body.String(), "request_id") || w.Header().Get("X-Request-ID") != "" {
			t.Fatal("unbounded or ambiguous request ID reflected", w.Body.String())
		}
	}
}

func TestErrorContractValidationDoesNotEchoRejectedInput(t *testing.T) {
	for _, body := range []string{`{"secret-token":"private-value"}`, `{"name":"private-value"} trailing`, `{"name":"` + strings.Repeat("private-value", 4000) + `"}`} {
		var input struct {
			Name string `json:"name"`
		}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Request-ID", "caller-controlled-secret")
		w := httptest.NewRecorder()
		if Decode(w, r, &input) || w.Code != 400 || strings.Contains(w.Body.String(), "private-value") || strings.Contains(w.Body.String(), "secret-token") || strings.Contains(w.Body.String(), "caller-controlled-secret") {
			t.Fatal("invalid input accepted or disclosed", w.Code, w.Body.String())
		}
	}
}
