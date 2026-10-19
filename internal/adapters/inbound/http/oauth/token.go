// Package oauth maps Fosite protocol callbacks into application services.
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
)

type callerContextKey struct{}

// WithCaller is used only after client authentication and sender-proof validation
// in a trusted endpoint adapter. No caller fields are decoded from token form data.
func WithCaller(ctx context.Context, caller tokens.Caller) context.Context {
	return context.WithValue(ctx, callerContextKey{}, caller)
}

type TokenHandler struct {
	scope   grants.Scope
	service *tokens.Service
	hasher  tokens.SecretHasher
}

var _ fosite.TokenEndpointHandler = (*TokenHandler)(nil)

func New(scope grants.Scope, service *tokens.Service, hashers ...tokens.SecretHasher) (*TokenHandler, error) {
	if !scope.Valid() || service == nil {
		return nil, tokens.ErrUnavailable
	}
	h := &TokenHandler{scope: scope, service: service}
	if len(hashers) == 1 {
		h.hasher = hashers[0]
	}
	return h, nil
}
func (*TokenHandler) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool { return false }
func (*TokenHandler) CanHandleTokenEndpointRequest(_ context.Context, r fosite.AccessRequester) bool {
	return r.GetGrantTypes().ExactOne(tokens.AuthorizationCode) || r.GetGrantTypes().ExactOne(tokens.RefreshToken)
}
func (h *TokenHandler) command(ctx context.Context, r fosite.AccessRequester) (tokens.Command, error) {
	caller, ok := ctx.Value(callerContextKey{}).(tokens.Caller)
	if !ok || caller.Scope != h.scope || r.GetClient() == nil || caller.ClientID != r.GetClient().GetID() {
		return tokens.Command{}, fosite.ErrInvalidClient
	}
	if !h.CanHandleTokenEndpointRequest(ctx, r) {
		return tokens.Command{}, fosite.ErrUnknownRequest
	}
	form := r.GetRequestForm()
	if form.Has("scope") && !grants.ValidScopes(strings.Split(form.Get("scope"), " ")) {
		return tokens.Command{}, fosite.ErrInvalidScope
	}
	if len(form) > 32 {
		return tokens.Command{}, fosite.ErrInvalidRequest
	}
	for key, values := range form {
		limit := 8192
		if key == "authorization_details" {
			limit = MaxAuthorizationDetailsBytes
		}
		if key == "client_assertion" {
			limit = 16384
		}
		if len(values) != 1 || len(values[0]) > limit {
			return tokens.Command{}, fosite.ErrInvalidRequest
		}
	}
	resources := form["resource"]
	if len(resources) != 1 || resources[0] == "" || len(resources[0]) > 2048 {
		return tokens.Command{}, fosite.ErrInvalidRequest.WithHint("Exactly one resource is required.")
	}
	kind := r.GetGrantTypes()[0]
	parameter := "code"
	if kind == tokens.RefreshToken {
		parameter = "refresh_token"
	}
	secret := form.Get(parameter)
	if secret == "" || len(secret) > 4096 {
		return tokens.Command{}, fosite.ErrInvalidGrant
	}
	var objects []grants.ObjectDetail
	if values, present := form["authorization_details"]; present {
		var err error
		objects, err = decodeObjectDetails(values[0], resources[0])
		if err != nil || len(objects) == 0 {
			return tokens.Command{}, fosite.ErrInvalidRequest
		}
		requested, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: caller.Scope, Resource: resources[0], Details: objects})
		if err != nil {
			return tokens.Command{}, fosite.ErrInvalidRequest
		}
		objects = requested.Snapshot().Details
	}
	digest := sha256.Sum256([]byte(secret))
	hash := hex.EncodeToString(digest[:])
	if h.hasher != nil {
		var err error
		hash, err = h.hasher.Digest(caller.Scope, kind, secret)
		if err != nil {
			return tokens.Command{}, fosite.ErrInvalidGrant
		}
	}
	cmd := tokens.Command{Caller: caller, Kind: kind, CredentialHash: hash, Resource: resources[0], Verifier: form.Get("code_verifier"), RedirectURI: form.Get("redirect_uri"), Objects: objects, WireScopesSpecified: form.Has("scope")}
	for _, name := range r.GetRequestedScopes() {
		switch name {
		case "openid":
			cmd.OIDCRequested = true
		case "offline_access":
			cmd.OfflineRequested = true
		default:
			cmd.Scopes = append(cmd.Scopes, name)
		}
	}
	if cmd.WireScopesSpecified && len(cmd.Scopes) == 0 {
		return tokens.Command{}, fosite.ErrInvalidScope
	}
	return cmd, nil
}
func (h *TokenHandler) HandleTokenEndpointRequest(ctx context.Context, r fosite.AccessRequester) error {
	_, err := h.command(ctx, r)
	return err
}
func (h *TokenHandler) PopulateTokenEndpointResponse(ctx context.Context, r fosite.AccessRequester, response fosite.AccessResponder) error {
	command, err := h.command(ctx, r)
	if err != nil {
		return err
	}
	result, err := h.service.Redeem(ctx, command)
	if errors.Is(err, tokens.ErrInvalidCredential) {
		return fosite.ErrInvalidGrant
	}
	if err != nil {
		return fosite.ErrTemporarilyUnavailable
	}
	return writeTokenResponse(response, result)
}
func writeTokenResponse(response fosite.AccessResponder, result tokens.Result) error {
	if !result.Claims.ObjectCeiling.IsZero() {
		details, err := EncodeAuthorizationDetails(result.Claims.ObjectCeiling, result.ObjectProfiles...)
		if err != nil {
			return fosite.ErrTemporarilyUnavailable
		}
		response.SetExtra("authorization_details", json.RawMessage(details))
	}
	response.SetAccessToken(result.AccessToken)
	response.SetTokenType("Bearer")
	if result.Claims.BindingThumbprint != "" {
		response.SetTokenType("DPoP")
	}
	response.SetExpiresIn(result.Claims.ExpiresAt.Sub(result.Claims.IssuedAt).Truncate(time.Second))
	scopes := append([]string(nil), result.Claims.Scopes...)
	if result.OIDC {
		scopes = append(scopes, "openid")
	}
	if result.OfflineAccess {
		scopes = append(scopes, "offline_access")
	}
	response.SetScopes(scopes)
	if result.IDToken != "" {
		response.SetExtra("id_token", result.IDToken)
	}
	if result.RefreshToken != "" {
		response.SetExtra("refresh_token", result.RefreshToken)
	}
	return nil
}
