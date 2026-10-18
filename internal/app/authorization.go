package app

import (
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/services/authorization"
)

// NewAuthorization assembles the first P2 consent boundary. It is not wired to
// public routes until upstream login and browser-session creation are complete.
func NewAuthorization(store authorization.Store, clock authorization.Clock) (*authorization.Service, error) {
	return authorization.New(store, clock, cryptoadapter.NewAuthorizationSource())
}
