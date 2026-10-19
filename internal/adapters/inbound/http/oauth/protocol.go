package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ory/fosite"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authorization"
	"github.com/startificial/mayi/internal/services/clients"
	"github.com/startificial/mayi/internal/services/tokens"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type protocolPrincipalKey struct{}
type protocolRegistry struct{}

var _ fosite.Storage = (*protocolRegistry)(nil)

func (*protocolRegistry) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	p, ok := ctx.Value(protocolPrincipalKey{}).(clients.Principal)
	if !ok || id != p.Client.ID {
		return nil, fosite.ErrInvalidClient
	}
	return protocolClient(p), nil
}
func (*protocolRegistry) ClientAssertionJWTValid(context.Context, string) error {
	return fosite.ErrInvalidClient
}
func (*protocolRegistry) SetClientAssertionJWT(context.Context, string, time.Time) error {
	return fosite.ErrInvalidClient
}
func protocolClient(p clients.Principal) fosite.Client {
	grants := []string{tokens.AuthorizationCode, tokens.RefreshToken}
	if p.Client.Machine {
		grants = []string{"client_credentials"}
	}
	scopes := append(append([]string(nil), p.Scopes...), "openid", "offline_access")
	return &fosite.DefaultClient{ID: p.Client.ID, Public: p.Client.AuthMethod == "none" || p.Client.AuthMethod == "", GrantTypes: grants, ResponseTypes: []string{"code"}, RedirectURIs: p.Client.RedirectURIs, Scopes: scopes}
}

type Protocol struct {
	scope    grants.Scope
	auth     *clients.Service
	consent  *authorization.Service
	status   *tokens.StatusService
	provider *fosite.Fosite
	proof    *tokens.ProofService
}

func NewPushed(scope grants.Scope, auth *clients.Service, consent *authorization.Service) (*Protocol, error) {
	if !scope.Valid() || auth == nil || consent == nil {
		return nil, tokens.ErrUnavailable
	}
	return &Protocol{scope: scope, auth: auth, consent: consent}, nil
}
func NewProtocol(scope grants.Scope, auth *clients.Service, consent *authorization.Service, issuance *tokens.Service, machine *tokens.MachineService, status *tokens.StatusService, hash tokens.SecretHasher, proof *tokens.ProofService) (*Protocol, error) {
	if !scope.Valid() || auth == nil || consent == nil || issuance == nil || machine == nil || status == nil || hash == nil || proof == nil {
		return nil, tokens.ErrUnavailable
	}
	h, err := New(scope, issuance, hash)
	if err != nil {
		return nil, err
	}
	config := &fosite.Config{ClientAuthenticationStrategy: func(ctx context.Context, _ *http.Request, form url.Values) (fosite.Client, error) {
		p, ok := ctx.Value(protocolPrincipalKey{}).(clients.Principal)
		if !ok || p.Client.ID != form.Get("client_id") {
			return nil, fosite.ErrInvalidClient
		}
		return protocolClient(p), nil
	}}
	config.TokenEndpointHandlers.Append(h)
	config.TokenEndpointHandlers.Append(&machineHandler{machine})
	return &Protocol{scope: scope, auth: auth, consent: consent, status: status, provider: fosite.NewOAuth2Provider(&protocolRegistry{}, config), proof: proof}, nil
}
func protocolError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="mayi"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{code})
}
func protocolForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != "POST" || r.URL.RawQuery != "" || err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 {
		protocolError(w, "invalid_request", 400)
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxPushedFormBytes))
	if err != nil {
		protocolError(w, "invalid_request", 400)
		return nil, false
	}
	v, err := pushedForm(string(body), MaxPushedFormBytes, map[string]int{
		"client_id": 70, "client_assertion_type": 80, "client_assertion": 16384, "grant_type": 64, "code": 256, "refresh_token": 256, "code_verifier": 128, "redirect_uri": 2048, "resource": 2048, "scope": 8192, "authorization_details": MaxAuthorizationDetailsBytes,
		"response_type": 4, "state": 1024, "code_challenge": 43, "code_challenge_method": 4, "nonce": 256, "dpop_jkt": 43, "token": 65536, "token_type_hint": 64, "dpop": 8192, "method": 16, "url": 2048,
	})
	if err != nil {
		protocolError(w, "invalid_request", 400)
		return nil, false
	}
	return v, true
}
func (h *Protocol) authenticate(ctx context.Context, r *http.Request, v url.Values) (clients.Principal, error) {
	p := clients.Proof{ClientID: v.Get("client_id"), Method: "none", Audience: h.scope.Issuer + "/token"}
	if len(r.Header.Values("Authorization")) > 1 {
		return clients.Principal{}, clients.ErrDenied
	}
	if r.Header.Get("Authorization") != "" {
		id, secret, ok := r.BasicAuth()
		if !ok || v.Has("client_assertion") || v.Has("client_assertion_type") {
			return clients.Principal{}, clients.ErrDenied
		}
		var err error
		p.ClientID, err = url.QueryUnescape(id)
		if err != nil {
			return clients.Principal{}, clients.ErrDenied
		}
		p.Secret, err = url.QueryUnescape(secret)
		if err != nil {
			return clients.Principal{}, clients.ErrDenied
		}
		if v.Has("client_id") && v.Get("client_id") != p.ClientID {
			return clients.Principal{}, clients.ErrDenied
		}
		p.Method = "client_secret_basic"
	} else if v.Has("client_assertion") || v.Has("client_assertion_type") {
		if v.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return clients.Principal{}, clients.ErrDenied
		}
		p.Method = "private_key_jwt"
		p.Assertion = v.Get("client_assertion")
	}
	principal, err := h.auth.Authenticate(ctx, p)
	if err != nil {
		return clients.Principal{}, err
	}
	v.Set("client_id", principal.Client.ID)
	return principal, nil
}
func authFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, clients.ErrUnavailable) {
		protocolError(w, "temporarily_unavailable", 503)
	} else {
		protocolError(w, "invalid_client", 401)
	}
}
func (h *Protocol) Push(w http.ResponseWriter, r *http.Request) {
	v, ok := protocolForm(w, r)
	if !ok {
		return
	}
	principal, err := h.authenticate(r.Context(), r, v)
	if err != nil {
		authFailure(w, err)
		return
	}
	if principal.Client.Machine {
		protocolError(w, "unauthorized_client", 400)
		return
	}
	v.Del("client_assertion")
	v.Del("client_assertion_type")
	request, err := DecodePushedInput(v.Encode(), h.scope)
	if err != nil {
		protocolError(w, "invalid_request", 400)
		return
	}
	result, err := h.consent.PushAuthenticated(r.Context(), request, principal.Version)
	if err != nil {
		if errors.Is(err, authorization.ErrUnavailable) {
			protocolError(w, "temporarily_unavailable", 503)
		} else {
			protocolError(w, "invalid_request", 400)
		}
		return
	}
	body, err := EncodePushedResponse(result, time.Now())
	if err != nil {
		protocolError(w, "temporarily_unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(201)
	_, _ = w.Write(body)
}
func (h *Protocol) Token(w http.ResponseWriter, r *http.Request) {
	v, ok := protocolForm(w, r)
	if !ok {
		return
	}
	principal, err := h.authenticate(r.Context(), r, v)
	if err != nil {
		authFailure(w, err)
		return
	}
	if !allowedFields(v, "client_id", "client_assertion", "client_assertion_type", "grant_type", "code", "refresh_token", "code_verifier", "redirect_uri", "resource", "scope", "authorization_details") {
		protocolError(w, "invalid_request", 400)
		return
	}
	caller := tokens.Caller{Scope: h.scope, ClientID: principal.Client.ID, AuthenticationVersion: principal.Version}
	if len(r.Header.Values("DPoP")) > 1 {
		protocolError(w, "invalid_dpop_proof", 400)
		return
	}
	if proof := r.Header.Get("DPoP"); proof != "" {
		caller.BindingThumbprint, err = h.proof.Verify(r.Context(), h.scope, tokens.ProofRequest{JWT: proof, Method: "POST", URL: h.scope.Issuer + "/token"})
		if err != nil {
			protocolError(w, "invalid_dpop_proof", 400)
			return
		}
	}
	ctx := WithCaller(context.WithValue(r.Context(), protocolPrincipalKey{}, principal), caller)
	r.PostForm = v
	r.Form = v
	request, err := h.provider.NewAccessRequest(ctx, r, &fosite.DefaultSession{})
	if err == nil {
		var response fosite.AccessResponder
		response, err = h.provider.NewAccessResponse(ctx, request)
		if err == nil {
			h.provider.WriteAccessResponse(ctx, w, request, response)
			return
		}
	}
	code := "invalid_request"
	status := 400
	switch {
	case errors.Is(err, fosite.ErrInvalidGrant):
		code = "invalid_grant"
	case errors.Is(err, fosite.ErrInvalidScope):
		code = "invalid_scope"
	case errors.Is(err, fosite.ErrInvalidClient):
		code = "invalid_client"
		status = 401
	case errors.Is(err, fosite.ErrTemporarilyUnavailable):
		code = "temporarily_unavailable"
		status = 503
	}
	protocolError(w, code, status)
}
func allowedFields(v url.Values, names ...string) bool {
	for key := range v {
		found := false
		for _, name := range names {
			if key == name {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func statusPrincipal(scope grants.Scope, p clients.Principal) tokens.StatusCaller {
	return tokens.StatusCaller{Scope: scope, ClientID: p.Client.ID, AuthenticationVersion: p.Version, Resources: p.Resources, Introspection: p.Client.Introspection}
}
func (h *Protocol) Introspect(w http.ResponseWriter, r *http.Request) {
	v, ok := protocolForm(w, r)
	if !ok {
		return
	}
	p, err := h.authenticate(r.Context(), r, v)
	if err != nil {
		authFailure(w, err)
		return
	}
	if !allowedFields(v, "client_id", "client_assertion", "client_assertion_type", "token", "token_type_hint", "resource", "dpop", "method", "url") || !v.Has("token") {
		protocolError(w, "invalid_request", 400)
		return
	}
	resource := v.Get("resource")
	if resource == "" && len(p.Resources) == 1 {
		resource = p.Resources[0]
	}
	result, err := h.status.Introspect(r.Context(), statusPrincipal(h.scope, p), v.Get("token"), resource)
	if err != nil {
		if errors.Is(err, tokens.ErrInvalidCredential) {
			protocolError(w, "invalid_client", 401)
		} else {
			protocolError(w, "temporarily_unavailable", 503)
		}
		return
	}
	verified := false
	if result.Claims.ID != "" && v.Has("dpop") {
		target, parseErr := url.Parse(v.Get("url"))
		aud, audErr := url.Parse(resource)
		if parseErr != nil || audErr != nil || target.Scheme != aud.Scheme || target.Host != aud.Host || target.User != nil || target.Fragment != "" || target.RawQuery != "" || (target.Path != aud.Path && !strings.HasPrefix(target.Path, strings.TrimSuffix(aud.Path, "/")+"/")) {
			writeIntrospection(w, tokens.Result{}, false)
			return
		}
		thumb, err := h.proof.Verify(r.Context(), h.scope, tokens.ProofRequest{JWT: v.Get("dpop"), Method: v.Get("method"), URL: v.Get("url"), AccessToken: v.Get("token")})
		if err != nil || thumb != result.Claims.BindingThumbprint {
			writeIntrospection(w, tokens.Result{}, false)
			return
		}
		verified = true
	}
	writeIntrospection(w, result, verified)
}
func (h *Protocol) Revoke(w http.ResponseWriter, r *http.Request) {
	v, ok := protocolForm(w, r)
	if !ok {
		return
	}
	p, err := h.authenticate(r.Context(), r, v)
	if err != nil {
		authFailure(w, err)
		return
	}
	if !allowedFields(v, "client_id", "client_assertion", "client_assertion_type", "token", "token_type_hint") || !v.Has("token") {
		protocolError(w, "invalid_request", 400)
		return
	}
	if err := h.status.Revoke(r.Context(), statusPrincipal(h.scope, p), v.Get("token"), v.Get("token_type_hint")); err != nil {
		protocolError(w, "temporarily_unavailable", 503)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
}
func writeIntrospection(w http.ResponseWriter, r tokens.Result, verified bool) {
	value := map[string]any{"active": false}
	if r.Claims.ID != "" {
		details, err := EncodeAuthorizationDetails(r.Claims.ObjectCeiling, r.ObjectProfiles...)
		if err != nil {
			protocolError(w, "temporarily_unavailable", 503)
			return
		}
		c := r.Claims
		value = map[string]any{"active": true, "iss": c.Scope.Issuer, "tenant_id": c.Scope.TenantID, "sub": c.Subject, "aud": c.Resource, "client_id": c.ClientID, "jti": c.ID, "grant_id": c.GrantID, "grant_revision": c.Revision, "principal_type": c.PrincipalType, "scope": strings.Join(c.Scopes, " "), "iat": c.IssuedAt.Unix(), "exp": c.ExpiresAt.Unix(), "authorization_details": json.RawMessage(details), "token_type": "Bearer", "mayi_proof_verified": verified}
		if c.BindingThumbprint != "" {
			value["cnf"] = map[string]string{"jkt": c.BindingThumbprint}
			value["token_type"] = "DPoP"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(value)
}
