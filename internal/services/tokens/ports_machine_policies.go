package tokens

import (
	"context"
	"github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
)

type MachinePolicyStore interface {
	ManageMachinePolicy(context.Context, grants.Scope, func(MachinePolicyManagement) error) error
}
type MachinePolicyManagement interface {
	Registration(context.Context, string, string) (authorization.Registration, error)
	// Set, policy-version increment and audit/outbox commit atomically while the
	// tenant's exclusive coordination lock excludes issuance and online decisions.
	SetMachineAuthorization(context.Context, MachineAuthorization, bool, string) error
}
