// Package audit contains credential-free delivery envelopes.
package audit

import (
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type Event struct {
	ID                  int64
	Scope               grants.Scope
	Type, Actor, Object string
	GrantID, IssuanceID string
	OccurredAt          time.Time
}
type Delivery struct {
	Event   Event
	Attempt int64
}
