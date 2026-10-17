package health

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
)

type Database interface{ CheckHealth(context.Context) error }
type KeyState interface {
	ActiveSigningKey(context.Context, grants.Scope) (int, error)
}
type Signer interface {
	Check(context.Context, grants.Scope, int) error
}
