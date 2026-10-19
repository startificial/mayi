package delivery

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
)

type SecurityStore interface {
	RecordDenied(context.Context, grants.Scope, string, int) error
}
