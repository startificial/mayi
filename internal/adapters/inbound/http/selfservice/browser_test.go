package selfservice

import (
	"github.com/startificial/mayi/internal/services/authorization"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationResponseRetainsRegisteredQueryBytes(t *testing.T) {
	for _, base := range []string{"https://app.example/cb?next=%2fhome&x=one%20two&x=three&flag", "https://app.example/cb?provider=mayi&", "https://app.example/cb?", "https://app.example/cb"} {
		for _, code := range []string{"one-use-code", ""} {
			out, err := responseRedirect(authorization.DecisionResult{RedirectURI: base, State: "state +/&", Code: code}, "https://auth.example/t/a")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(out, base) {
				t.Fatal("registered redirect query bytes changed", out)
			}
			u, err := url.Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if q.Get("state") != "state +/&" || q.Get("iss") != "https://auth.example/t/a" || q.Get("code") != code || code == "" && q.Get("error") != "access_denied" {
				t.Fatal("invalid protocol response", out)
			}
			if strings.Contains(base, "next=") && (q.Get("next") != "/home" || strings.Join(q["x"], "|") != "one two|three") {
				t.Fatal("fixed query semantics changed", out)
			}
		}
	}
}
