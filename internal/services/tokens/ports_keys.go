package tokens

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
)

// ActiveKeyReader resolves the authoritative, tenant-specific signing version.
type ActiveKeyReader interface {
	ActiveSigningKey(context.Context, grants.Scope) (int, error)
}
