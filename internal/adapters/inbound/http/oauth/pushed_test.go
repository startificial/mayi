package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/authorization"
)

func pushedFields() url.Values {
	return url.Values{"client_id": {"web"}, "response_type": {"code"}, "redirect_uri": {"https://app.example/cb?provider=mayi"}, "resource": {"https://api.example/documents"}, "scope": {"read write"}, "state": {"unpredictable-state-16"}, "code_challenge": {strings.Repeat("A", 43)}, "code_challenge_method": {"S256"}, "authorization_details": {rarRequest()}}
}

func mixedProfiles(t testing.TB) ([]resources.ObjectProfile, string) {
	t.Helper()
	first := rarProfile(t)
	s := first.Snapshot()
	s.Type = "https://api.example/types/workflow/v1"
	s.Actions = []resources.ObjectAction{{Name: "execute", Description: "Execute workflow"}}
	second, err := resources.NewObjectProfile(s)
	if err != nil {
		t.Fatal(err)
	}
	return []resources.ObjectProfile{first, second}, "[" + rarEntry("123", "read") + `,{"type":"https://api.example/types/workflow/v1","locations":["https://api.example/documents"],"identifier":"123","actions":["execute"]}]`
}

func TestPushedWirePreservesMixedTypesAndExactRequestValues(t *testing.T) {
	profiles, raw := mixedProfiles(t)
	v := pushedFields()
	v.Set("authorization_details", raw)
	v.Set("state", "original&state=123%2F+same")
	r, err := DecodePushedRequest(v.Encode(), profiles[0].Snapshot().Scope, profiles...)
	if err != nil || r.State != v.Get("state") || r.RedirectURI != v.Get("redirect_uri") || r.ClientID != "web" || r.PKCEChallenge != v.Get("code_challenge") || len(r.PermissionScopes) != 2 || !r.ObjectCeiling.Permits(r.TenantIssuer, r.ResourceURI, profiles[1].Snapshot().Type, "123", "execute") || r.ObjectCeiling.Permits(r.TenantIssuer, r.ResourceURI, profiles[0].Snapshot().Type, "123", "execute") {
		t.Fatal("wire mapping changed exact request correlation", err)
	}
	encoded, err := EncodeAuthorizationDetails(r.ObjectCeiling, profiles...)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeAuthorizationDetails(string(encoded), profiles...)
	if err != nil || !back.Equal(r.ObjectCeiling) {
		t.Fatal("mixed-type round trip changed authority", err)
	}
	for _, ps := range [][]resources.ObjectProfile{nil, {profiles[0]}, {profiles[1]}, {profiles[0], profiles[0]}} {
		if out, err := DecodeAuthorizationDetails(raw, ps...); !errors.Is(err, ErrInvalidAuthorizationDetails) || !out.IsZero() {
			t.Fatal("missing or ambiguous profile accepted", err)
		}
	}
	// JSON formatting whitespace is valid inside a form value, never a new
	// form field. Identifier/state bytes are still checked by domain rules.
	v.Set("authorization_details", strings.ReplaceAll(raw, ",", ",\r\n"))
	if _, err := DecodePushedRequest(v.Encode(), r.TenantIssuer, profiles...); err != nil {
		t.Fatal("valid JSON whitespace rejected", err)
	}
}

func TestPushedWireRejectsUnsupportedOrAmbiguousRequests(t *testing.T) {
	p := rarProfile(t)
	for _, key := range []string{"client_id", "response_type", "redirect_uri", "resource", "scope", "state", "code_challenge", "code_challenge_method", "authorization_details"} {
		for _, mode := range []string{"missing", "empty", "duplicate"} {
			t.Run(key+"/"+mode, func(t *testing.T) {
				v := pushedFields()
				switch mode {
				case "missing":
					v.Del(key)
				case "empty":
					v.Set(key, "")
				case "duplicate":
					v.Add(key, v.Get(key))
				}
				assertPushedInvalid(t, v.Encode(), p)
			})
		}
	}
	for key, value := range map[string]string{"request": "signed-object", "request_uri": "https://evil.example/request", "client_secret": "private-secret", "client_assertion": "private-assertion", "dpop_jkt": "invalid-key", "tenant_id": "other", "nonce": "unsupported", "Scope": "read"} {
		v := pushedFields()
		v.Set(key, value)
		assertPushedInvalid(t, v.Encode(), p)
	}
	for key, values := range map[string][]string{
		"response_type": {"token", "code token"}, "code_challenge_method": {"plain", "s256"},
		"code_challenge": {"short", strings.Repeat("A", 42) + "B"}, "client_id": {"other/client", strings.Repeat("a", 65)},
		"redirect_uri":          {"https://app.example/cb#secret", "http://app.example/cb"},
		"resource":              {"https://other.example/documents", "https://api.example/documents/child"},
		"state":                 {"short", "unpredictable-state\r\n", strings.Repeat("a", 1025)},
		"scope":                 {"read read", " read", "read  write", "read\twrite"},
		"authorization_details": {"[]", "null", strings.Replace(rarRequest(), "document/v1", "document/v2", 1)},
	} {
		for _, value := range values {
			v := pushedFields()
			v.Set(key, value)
			assertPushedInvalid(t, v.Encode(), p)
		}
	}
	valid := pushedFields().Encode()
	for _, raw := range []string{"", valid + "&", "&" + valid, valid + "&%63lient_id=web", valid + "&unknown", strings.Replace(valid, "client_id=web", "client_id=%zz", 1), strings.Replace(valid, "client_id=web", "client_id=%FF", 1), strings.Replace(valid, "client_id=web", "%zz=web", 1), strings.Repeat("x", MaxPushedFormBytes+1)} {
		assertPushedInvalid(t, raw, p)
	}
	if out, err := DecodePushedRequest(valid, grants.Scope{TenantID: "other", Issuer: p.Snapshot().Scope.Issuer}, p); !errors.Is(err, ErrInvalidPushedRequest) || out.ClientID != "" {
		t.Fatal("foreign tenant wire request accepted", err)
	}
}

func assertPushedInvalid(t *testing.T, raw string, p resources.ObjectProfile) {
	t.Helper()
	out, err := DecodePushedRequest(raw, p.Snapshot().Scope, p)
	if !errors.Is(err, ErrInvalidPushedRequest) || out.ClientID != "" || !out.ObjectCeiling.IsZero() || (err.Error() != "invalid pushed authorization request" && err.Error() != "invalid pushed authorization request\ninvalid authorization details") {
		t.Fatal("invalid wire request returned data or unsafe diagnostics", err)
	}
}

func TestPushedResponseAndFrontChannelReferenceRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	reference := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("r", 32)))
	result := authorization.PushedResult{Reference: reference, ExpiresAt: now.Add(90 * time.Second)}
	for _, elapsed := range []time.Duration{0, time.Nanosecond, time.Second, 89 * time.Second} {
		data, err := EncodePushedResponse(result, now.Add(elapsed))
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			RequestURI string `json:"request_uri"`
			ExpiresIn  int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(data, &response); err != nil || response.ExpiresIn < 1 || time.Duration(response.ExpiresIn)*time.Second > result.ExpiresAt.Sub(now.Add(elapsed)) {
			t.Fatal("expiry extended or response invalid", err)
		}
		p := rarProfile(t).Snapshot()
		browserHash := strings.Repeat("b", 64)
		proof, err := DecodePushedAuthorization(url.Values{"client_id": {"web"}, "request_uri": {response.RequestURI}}.Encode(), p.Scope, browserHash)
		hash := sha256.Sum256([]byte(reference))
		if err != nil || proof.ReferenceHash != hex.EncodeToString(hash[:]) || proof.ClientID != "web" || proof.BrowserBindingHash != browserHash || proof.TenantIssuer != p.Scope {
			t.Fatal("reference did not preserve exact service binding", err)
		}
	}
	for _, at := range []time.Time{{}, now.Add(-time.Second), now.Add(89*time.Second + time.Nanosecond), result.ExpiresAt} {
		if out, err := EncodePushedResponse(result, at); !errors.Is(err, ErrInvalidPushedRequest) || len(out) != 0 {
			t.Fatal("invalid result lifetime emitted", err)
		}
	}
	for _, raw := range []string{"", "secret", reference + "=", strings.Repeat("A", 42) + "B", reference + "?next=x"} {
		result.Reference = raw
		if out, err := EncodePushedResponse(result, now); err == nil || len(out) != 0 {
			t.Fatal("invalid raw reference emitted", err)
		}
	}
}

func TestPushedFrontChannelRejectsFetchingReplacementAndAmbiguity(t *testing.T) {
	s := rarProfile(t).Snapshot().Scope
	browserHash := strings.Repeat("b", 64)
	reference := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("r", 32)))
	v := url.Values{"client_id": {"web"}, "request_uri": {pushedURIPrefix + reference}}
	deny := func(raw string) {
		t.Helper()
		out, err := DecodePushedAuthorization(raw, s, browserHash)
		if !errors.Is(err, ErrInvalidPushedRequest) || out.ClientID != "" || err.Error() != "invalid pushed authorization request" {
			t.Fatal("unsupported reference returned data", err)
		}
	}
	for _, uri := range []string{"https://evil.example/request", "http://127.0.0.1:8200/secret", "urn:other:" + reference, strings.ToUpper(pushedURIPrefix) + reference, reference, pushedURIPrefix + reference + "=", pushedURIPrefix + reference + "#fragment", pushedURIPrefix + strings.Repeat("A", 42) + "B"} {
		bad := v.Clone()
		bad.Set("request_uri", uri)
		deny(bad.Encode())
	}
	for _, key := range []string{"resource", "redirect_uri", "scope", "authorization_details", "state", "code_challenge", "response_type", "request", "dpop_jkt"} {
		bad := v.Clone()
		bad.Set(key, "replacement")
		deny(bad.Encode())
	}
	for _, raw := range []string{"", "client_id=web", "request_uri=" + url.QueryEscape(v.Get("request_uri")), v.Encode() + "&request_uri=" + url.QueryEscape(v.Get("request_uri")), v.Encode() + "&%63lient_id=web", v.Encode() + "&", strings.Repeat("x", MaxPushedAuthorizationBytes+1)} {
		deny(raw)
	}
	for _, scope := range []grants.Scope{{}, {TenantID: "a", Issuer: "bad\r\nissuer"}} {
		if _, err := DecodePushedAuthorization(v.Encode(), scope, browserHash); err == nil {
			t.Fatal("untrusted issuer context accepted")
		}
	}
	if _, err := DecodePushedAuthorization(v.Encode(), s, "raw-browser-value"); err == nil {
		t.Fatal("invalid browser proof accepted")
	}
}

func FuzzPushedWire(f *testing.F) {
	profiles, mixed := mixedProfiles(f)
	v := pushedFields()
	v.Set("authorization_details", mixed)
	for _, seed := range []string{v.Encode(), "", "client_id=web&%63lient_id=other", "client_id=%zz"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r, err := DecodePushedRequest(raw, profiles[0].Snapshot().Scope, profiles...)
		if err != nil {
			if !errors.Is(err, ErrInvalidPushedRequest) || r.ClientID != "" {
				t.Fatal("unclassified parse failure or partial request")
			}
			return
		}
		encoded, err := EncodeAuthorizationDetails(r.ObjectCeiling, profiles...)
		if err != nil || !r.Valid() {
			t.Fatal("accepted request cannot preserve its authority", err)
		}
		back, err := DecodeAuthorizationDetails(string(encoded), profiles...)
		if err != nil || !back.Equal(r.ObjectCeiling) {
			t.Fatal("wire round trip changed authority", err)
		}
	})
}
