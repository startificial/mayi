package app

import (
	"github.com/startificial/mayi/internal/services/authentication"
	"time"

	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/services/tokens"
)

// NewIssuance composes the P0 service. Durable storage, policy and KMS adapters
// remain required: no in-memory production fallback or development signing key.
func NewIssuance(policy tokens.Authorizer, clock tokens.Clock, signer tokens.Signer, material tokens.MaterialSource, store tokens.UnitOfWork, lifetime time.Duration, rules ...[]authentication.BudgetRule) (*tokens.Service, error) {
	selected := authentication.DefaultBudgetRules()
	if len(rules) > 1 {
		return nil, tokens.ErrUnavailable
	}
	if len(rules) == 1 {
		selected = rules[0]
	}
	admission, err := authentication.NewAdmission(store, selected)
	if err != nil {
		return nil, err
	}
	return tokens.New(policy, clock, cryptoadapter.New(), signer, material, store, lifetime, admission)
}
