package app

import (
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/services/authorization"
)

// NewAuthorization assembles the reusable P2 consent boundary.
func NewAuthorization(store authorization.Store, clock authorization.Clock) (*authorization.Service, error) {
	return authorization.New(store, clock, cryptoadapter.NewAuthorizationSource(), nil)
}

// NewObjectAuthorization requires an explicit resource-owned guard. The default
// server composition keeps object consent closed until an adapter is reviewed.
func NewObjectAuthorization(store authorization.Store, clock authorization.Clock, authority authorization.ObjectConsentAuthority) (*authorization.Service, error) {
	if authority == nil {
		return nil, authorization.ErrUnavailable
	}
	return authorization.New(store, clock, cryptoadapter.NewAuthorizationSource(), authority)
}
