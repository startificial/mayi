package app

import (
	"github.com/ory/fosite"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
)

// NewTokenHandler composes the P0 service-owned code/refresh handler. Do not also
// register Fosite's state-mutating default handlers for these two grants.
func NewTokenHandler(scope grants.Scope, service *tokens.Service) (fosite.TokenEndpointHandler, error) {
	return oauth.New(scope, service)
}
