package oauth

import (
	"context"
	"errors"
	"github.com/ory/fosite"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
	"strings"
)

type machineHandler struct{ service *tokens.MachineService }

var _ fosite.TokenEndpointHandler = (*machineHandler)(nil)

func (*machineHandler) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool { return false }
func (*machineHandler) CanHandleTokenEndpointRequest(_ context.Context, r fosite.AccessRequester) bool {
	return r.GetGrantTypes().ExactOne("client_credentials")
}
func (*machineHandler) HandleTokenEndpointRequest(ctx context.Context, r fosite.AccessRequester) error {
	caller, ok := ctx.Value(callerContextKey{}).(tokens.Caller)
	if !ok || r.GetClient() == nil || caller.ClientID != r.GetClient().GetID() || r.GetRequestForm().Get("resource") == "" {
		return fosite.ErrInvalidClient
	}
	return nil
}
func (h *machineHandler) PopulateTokenEndpointResponse(ctx context.Context, r fosite.AccessRequester, response fosite.AccessResponder) error {
	if !h.CanHandleTokenEndpointRequest(ctx, r) {
		return fosite.ErrUnknownRequest
	}
	caller, ok := ctx.Value(callerContextKey{}).(tokens.Caller)
	if !ok {
		return fosite.ErrInvalidClient
	}
	form := r.GetRequestForm()
	if form.Has("code") || form.Has("refresh_token") || form.Has("redirect_uri") || form.Has("code_verifier") {
		return fosite.ErrInvalidRequest
	}
	var scopes []string
	if form.Has("scope") {
		scopes = strings.Split(form.Get("scope"), " ")
		if !grants.ValidScopes(scopes) {
			return fosite.ErrInvalidScope
		}
	}
	cmd := tokens.Command{Caller: caller, Resource: form.Get("resource"), Scopes: scopes}
	if form.Has("authorization_details") {
		details, err := decodeObjectDetails(form.Get("authorization_details"), cmd.Resource)
		if err != nil || len(details) == 0 {
			return fosite.ErrInvalidRequest
		}
		ceiling, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: caller.Scope, Resource: cmd.Resource, Details: details})
		if err != nil {
			return fosite.ErrInvalidRequest
		}
		cmd.Objects = ceiling.Snapshot().Details
	}
	result, err := h.service.Issue(ctx, cmd)
	if errors.Is(err, tokens.ErrInvalidDetails) {
		return (&fosite.RFC6749Error{ErrorField: "invalid_authorization_details", CodeField: 400}).WithWrap(err)
	}
	if errors.Is(err, tokens.ErrInvalidScope) {
		return fosite.ErrInvalidScope
	}
	if errors.Is(err, tokens.ErrInvalidCredential) {
		return fosite.ErrInvalidGrant
	}
	if err != nil {
		return fosite.ErrTemporarilyUnavailable.WithWrap(err)
	}
	return writeTokenResponse(response, result)
}
