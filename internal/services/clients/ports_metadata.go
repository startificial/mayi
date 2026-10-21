package clients

import (
	"context"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
)

type ClientMetadataResolver interface {
	ResolveClient(context.Context, grants.Scope, string, bool) (clients.Client, error)
}
