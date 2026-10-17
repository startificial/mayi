package delegation

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type Authorizer interface {
	AuthorizeExchange(context.Context, Command) (Edge, error)
}

// SubjectReader is a trusted online validation boundary. The future adapter must
// verify purpose, signature, exact recipient audience and current grant status.
// It must never interpret an unverified JWT's payload as an active Subject.
type SubjectReader interface {
	ReadSubject(context.Context, grants.Scope, string) (Subject, error)
}
type Clock interface{ Now() time.Time }
