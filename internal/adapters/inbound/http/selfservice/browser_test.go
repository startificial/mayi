package selfservice

import (
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authorization"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestScopeOnlyPreviewRejectsRARAndPushedRequestsBeforeServices(t *testing.T) {
	// Unset services make silently discarding object restrictions a hard failure.
	// The preview must reject these fields until the complete RAR/PAR path exists.
	h := &Handler{scope: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}}
	base := url.Values{
		"client_id": {"web"}, "response_type": {"code"}, "redirect_uri": {"https://app.example/cb"},
		"resource": {"https://api.example/documents"}, "scope": {"read"}, "state": {"unpredictable-client-state"},
		"code_challenge": {strings.Repeat("A", 43)}, "code_challenge_method": {"S256"},
	}
	for key, value := range map[string]string{
		"authorization_details": `[{"type":"https://api.example/types/document/v1","locations":["https://api.example/documents"],"identifier":"123","actions":["read"]}]`,
		"request_uri":           "urn:ietf:params:oauth:request_uri:pending-reference",
		"request":               "unsupported-signed-request",
	} {
		for _, value := range []string{value, ""} {
			t.Run(key+value, func(t *testing.T) {
				query := base.Encode() + "&" + url.Values{key: {value}}.Encode()
				r := httptest.NewRequest(http.MethodGet, "https://auth.example/t/a/authorize?"+query, nil)
				r.AddCookie(&http.Cookie{Name: h.name("browser"), Value: strings.Repeat("A", 43)})
				w := httptest.NewRecorder()
				h.Authorize(w, r)
				if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 || strings.TrimSpace(w.Body.String()) != `{"error":"invalid_request","message":"The request is malformed or contains unsupported values."}` {
					t.Fatalf("unsupported authority escaped the boundary: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

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

func TestConsentPolicyAllowsExactRegisteredReturnOrigin(t *testing.T) {
	policy, err := consentPolicy("https://app.example:8443/cb?provider=mayi")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(policy, "form-action 'self' https://app.example:8443;") || !strings.Contains(policy, "default-src 'none'") || !strings.Contains(policy, "frame-ancestors 'none'") || strings.Contains(policy, "*") {
		t.Fatal("unbounded consent policy", policy)
	}
	if strings.Contains(pagePolicy(""), "app.example") {
		t.Fatal("default policy trusts a client")
	}
	for _, redirect := range []string{"https://app.example.evil/cb\r\nX-Test:yes", "https://app.example/cb?state=ambiguous", "http://app.example/cb", "https://user@app.example/cb"} {
		if _, err := consentPolicy(redirect); err == nil {
			t.Fatal("unsafe policy input", redirect)
		}
	}
}
