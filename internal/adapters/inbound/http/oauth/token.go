// Package oauth maps Fosite protocol callbacks into application services.
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
}

var _ fosite.TokenEndpointHandler = (*TokenHandler)(nil)

func New(scope grants.Scope, service *tokens.Service) (*TokenHandler, error) {
	if !scope.Valid() || service == nil {
		return nil, tokens.ErrUnavailable
	}
	return &TokenHandler{scope: scope, service: service}, nil
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
	if len(form) > 32 {
		return tokens.Command{}, fosite.ErrInvalidRequest
	}
	for _, values := range form {
		if len(values) != 1 || len(values[0]) > 8192 {
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
	digest := sha256.Sum256([]byte(secret))
	return tokens.Command{Caller: caller, Kind: kind, CredentialHash: hex.EncodeToString(digest[:]), Resource: resources[0], Verifier: form.Get("code_verifier"), RedirectURI: form.Get("redirect_uri"), Scopes: []string(r.GetRequestedScopes())}, nil
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
	response.SetAccessToken(result.AccessToken)
	response.SetTokenType("Bearer")
	if result.Claims.BindingThumbprint != "" {
		response.SetTokenType("DPoP")
	}
	response.SetExpiresIn(result.Claims.ExpiresAt.Sub(result.Claims.IssuedAt).Truncate(time.Second))
	response.SetScopes(result.Claims.Scopes)
	if result.RefreshToken != "" {
		response.SetExtra("refresh_token", result.RefreshToken)
	}
	return nil
}
