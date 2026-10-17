package http

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictBoundedJSON(t *testing.T) {
	for _, body := range []string{`{"unknown":1}`, `{"name":"a"} {}`, `{"name":"` + strings.Repeat("a", 33<<10) + `"}`, `{"name":false}`, `null`} {
		var input struct {
			Name string `json:"name"`
		}
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		if Decode(w, r, &input) {
			t.Fatal("invalid request accepted")
		}
	}
}
