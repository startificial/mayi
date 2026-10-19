package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/authorization"
)

// MaxPushedFormBytes allows percent expansion of the bounded RAR envelope and
// the remaining bounded fields. Future handlers must bound reads before parsing.
const MaxPushedFormBytes = 128 << 10
const MaxPushedAuthorizationBytes = 2048
const pushedURIPrefix = "urn:ietf:params:oauth:request_uri:"

var ErrInvalidPushedRequest = errors.New("invalid pushed authorization request")

// DecodePushedRequest maps only the initial public-client code/S256 profile.
// Profiles come from trusted current client/resource registration, never form
// metadata. The service must recheck registration and policy before committing.
// No handler or public PAR route is enabled by these pure wire codecs.
func DecodePushedRequest(raw string, scope grants.Scope, profiles ...resources.ObjectProfile) (domain.Request, error) {
	v, err := pushedForm(raw, MaxPushedFormBytes, map[string]int{
		"client_id": 64, "response_type": 4, "redirect_uri": 2048,
		"resource": 2048, "scope": 8192, "state": 1024,
		"code_challenge": 43, "code_challenge_method": 4,
		"authorization_details": MaxAuthorizationDetailsBytes,
	})
	if err != nil || len(v) != 9 || !scope.Valid() || v.Get("response_type") != "code" || v.Get("code_challenge_method") != "S256" || len(v.Get("state")) < 16 {
		return domain.Request{}, ErrInvalidPushedRequest
	}
	ceiling, err := DecodeAuthorizationDetails(v.Get("authorization_details"), profiles...)
	if err != nil || !ceiling.BoundTo(scope, v.Get("resource")) {
		return domain.Request{}, ErrInvalidPushedRequest
	}
	r := domain.Request{TenantIssuer: scope, ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), ResourceURI: v.Get("resource"), PermissionScopes: strings.Split(v.Get("scope"), " "), State: v.Get("state"), PKCEChallenge: v.Get("code_challenge"), ObjectCeiling: ceiling}
	if !r.Valid() {
		return domain.Request{}, ErrInvalidPushedRequest
	}
	return r, nil
}

// DecodePushedAuthorization accepts only client_id and an opaque local URN.
// No URI is resolved or fetched. Issuer routing and the browser credential are
// supplied by a trusted adapter; correlation does not authenticate a client.
func DecodePushedAuthorization(raw string, scope grants.Scope, browserHash string) (authorization.PushedProof, error) {
	v, err := pushedForm(raw, MaxPushedAuthorizationBytes, map[string]int{"client_id": 64, "request_uri": len(pushedURIPrefix) + 43})
	if err != nil || len(v) != 2 || !strings.HasPrefix(v.Get("request_uri"), pushedURIPrefix) {
		return authorization.PushedProof{}, ErrInvalidPushedRequest
	}
	reference := strings.TrimPrefix(v.Get("request_uri"), pushedURIPrefix)
	if !pushedReference(reference) {
		return authorization.PushedProof{}, ErrInvalidPushedRequest
	}
	hash := sha256.Sum256([]byte(reference))
	proof := authorization.PushedProof{TenantIssuer: scope, ClientID: v.Get("client_id"), ReferenceHash: hex.EncodeToString(hash[:]), BrowserBindingHash: browserHash}
	if !proof.Valid() {
		return authorization.PushedProof{}, ErrInvalidPushedRequest
	}
	return proof, nil
}

// EncodePushedResponse emits the RFC 9126 success body only after a successful
// service commit. The caller supplies time; rounding down cannot extend expiry.
// A future endpoint supplies status 201, JSON and no-store response headers.
func EncodePushedResponse(result authorization.PushedResult, now time.Time) ([]byte, error) {
	lifetime := result.ExpiresAt.Sub(now)
	if now.IsZero() || !pushedReference(result.Reference) || lifetime < time.Second || lifetime > domain.PushedLifetime {
		return nil, ErrInvalidPushedRequest
	}
	return json.Marshal(struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int64  `json:"expires_in"`
	}{pushedURIPrefix + result.Reference, int64(lifetime / time.Second)})
}

func pushedReference(raw string) bool {
	if len(raw) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == raw
}

// Parse each form component exactly once, rejecting empty segments, unknown or
// repeated decoded names, invalid UTF-8 and percent encodings. Never merge a
// URL query with a POST body or silently ignore partially parsed input.
func pushedForm(raw string, limit int, fields map[string]int) (url.Values, error) {
	if len(raw) == 0 || len(raw) > limit {
		return nil, ErrInvalidPushedRequest
	}
	values := make(url.Values, len(fields))
	for _, pair := range strings.Split(raw, "&") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || len(values) >= len(fields) {
			return nil, ErrInvalidPushedRequest
		}
		key, err := url.QueryUnescape(key)
		if err != nil {
			return nil, ErrInvalidPushedRequest
		}
		bound, allowed := fields[key]
		if !allowed || values[key] != nil {
			return nil, ErrInvalidPushedRequest
		}
		value, err = url.QueryUnescape(value)
		if err != nil || len(value) == 0 || len(value) > bound || !utf8.ValidString(value) {
			return nil, ErrInvalidPushedRequest
		}
		values[key] = []string{value}
	}
	return values, nil
}
