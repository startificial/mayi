package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/startificial/mayi/internal/services/administration"
)

func TestErrorContractManagementMapsWrappedServiceErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{administration.ErrDenied, 403, "forbidden"},
		{administration.ErrInvalid, 400, "invalid_request"},
		{administration.ErrConflict, 409, "conflict"},
		{administration.ErrNotFound, 404, "not_found"},
		{administration.ErrUnavailable, 503, "temporarily_unavailable"},
		{errors.New("private-database-cause"), 503, "temporarily_unavailable"},
	} {
		t.Run(tc.code+tc.err.Error(), func(t *testing.T) {
			w := httptest.NewRecorder()
			failure(w, fmt.Errorf("secret-token: %w", tc.err))
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status || body["error"] != tc.code || body["message"] == "" || strings.Contains(w.Body.String(), "secret-token") || strings.Contains(w.Body.String(), "private-database-cause") {
				t.Fatalf("incorrect or unsafe mapping: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
