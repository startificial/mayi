package delivery

import (
	"context"
	"github.com/startificial/mayi/internal/domain/audit"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type Clock interface{ Now() time.Time }
type Store interface {
	ClaimEvent(context.Context, grants.Scope, time.Time, time.Duration) (audit.Delivery, bool, error)
	CompleteEvent(context.Context, audit.Delivery, time.Time) error
}
type Sink interface {
	Deliver(context.Context, audit.Event) error
}
