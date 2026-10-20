package integration_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
)

func TestP3PARProofHeaderPinsKeyAndRejectsMismatchedThumbprints(t *testing.T) {
	l := newLiveProtocol(t)
	ctx := context.Background()
	key := proofKey(t)
	if _, err := l.e.admin.Exec(ctx, `UPDATE mayi.clients SET require_binding=true WHERE tenant_id='a' AND client_id='web'`); err != nil {
		t.Fatal(err)
	}
	for _, bound := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "resource-bound"}[bound], func(t *testing.T) {
			handler := l.protocol
			target := l.proof.TenantIssuer.Issuer + "/par"
			if bound {
				var err error
				handler, err = oauth.NewResourcePushed(l.proof.TenantIssuer, l.clients, l.consent, "https://api.example", "api", l.proofs)
				if err != nil {
					t.Fatal(err)
				}
				target = l.proof.TenantIssuer.Issuer + "/r/api/par"
			}
			form := url.Values{"client_id": {"web"}, "response_type": {"code"}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "resource": {"https://api.example"}, "scope": {"read"}, "state": {"par-proof-state-at-least-16"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}, "authorization_details": {`[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"workflow:123","actions":["read"]}]`}}
			post := func(jwt string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("DPoP", jwt)
				w := httptest.NewRecorder()
				handler.Push(w, r)
				return w
			}
			signed := func(nonce, id string) string {
				return proof(t, key, map[string]any{"nonce": nonce, "htu": target, "jti": id + map[bool]string{false: "-ordinary", true: "-bound"}[bound]})
			}
			nonce := requireNonce(t, post(signed("", "par-initial-proof-123456")), 400)
			form.Set("dpop_jkt", thumbprint(t, proofKey(t)))
			requireProtocolError(t, post(signed(nonce, "par-mismatch-proof-123456")), 400, "invalid_dpop_proof")
			form.Del("dpop_jkt")
			w := post(signed(nonce, "par-header-only-proof-123456"))
			var result struct {
				URI string `json:"request_uri"`
			}
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
				t.Fatal("proof-header PAR failed", w.Code)
			}
			var boundThumb string
			if err := l.e.admin.QueryRow(ctx, `SELECT binding_thumbprint FROM mayi.pushed_requests WHERE tenant_id='a' AND reference_hash=$1`, secretHash(strings.TrimPrefix(result.URI, "urn:ietf:params:oauth:request_uri:"))).Scan(&boundThumb); err != nil || boundThumb != thumbprint(t, key) {
				t.Fatal("PAR did not pin proof key", err)
			}
			form.Set("dpop_jkt", thumbprint(t, key))
			if w := post(signed(nonce, "par-header-and-jkt-123456")); w.Code != 201 {
				t.Fatal("matching mechanisms rejected", w.Code)
			}
			wrong := proof(t, key, map[string]any{"nonce": nonce, "htu": l.proof.TenantIssuer.Issuer + "/token", "jti": "par-wrong-endpoint-123456"})
			requireProtocolError(t, post(wrong), 400, "invalid_dpop_proof")
		})
	}
}
