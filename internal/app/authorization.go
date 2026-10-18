package app

import (
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/services/authorization"
)

// NewAuthorization assembles the reusable P2 consent boundary.
func NewAuthorization(store authorization.Store, clock authorization.Clock) (*authorization.Service, error) {
	return authorization.New(store, clock, cryptoadapter.NewAuthorizationSource())
}
