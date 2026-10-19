package authentication

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
)

type AdmissionStore interface {
	// ConsumeBudget uses database time and one atomic finite counter update. It
	// must never allow requests when shared state is unavailable or ambiguous.
	ConsumeBudget(context.Context, grants.Scope, Budget) (bool, error)
}

// RequestAdmission is the narrow security contract used by authentication.
type RequestAdmission interface {
	Check(context.Context, grants.Scope, string, string, string) error
}
