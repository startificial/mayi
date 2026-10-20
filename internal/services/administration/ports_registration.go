package administration

import (
	"context"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
)

type RegistrationCredentials interface {
	InitialAccess(context.Context, grants.Scope, string) (bool, error)
	NewClientID(context.Context, grants.Scope) (string, error)
}

// Admission commits independently so rejected requests still consume budget.
type RegistrationAdmission interface {
	AdmitRegistration(context.Context, grants.Scope) (bool, error)
}

// The same tenant lock covers admission policy, quota, client/profile checks,
// insertion and audit. No external call occurs inside this transaction.
type RegistrationTransaction interface {
	RegistrationPolicy(context.Context) (clients.RegistrationPolicy, error)
	SetRegistrationPolicy(context.Context, clients.RegistrationPolicy) error
	DynamicClientCount(context.Context) (int, error)
	MarkDynamicClient(context.Context, string) error
}
