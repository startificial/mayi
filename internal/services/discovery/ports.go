package discovery

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
)

type Directory interface {
	PublishedKeys(context.Context, grants.Scope) ([]identity.PublicKey, error)
}
