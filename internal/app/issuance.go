package app

import (
	"time"

	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/services/tokens"
)

// NewIssuance composes the P0 service. Durable storage, policy and KMS adapters
// remain required: no in-memory production fallback or development signing key.
func NewIssuance(policy tokens.Authorizer, clock tokens.Clock, signer tokens.Signer, material tokens.MaterialSource, store tokens.UnitOfWork, lifetime time.Duration) (*tokens.Service, error) {
	return tokens.New(policy, clock, cryptoadapter.New(), signer, material, store, lifetime)
}
