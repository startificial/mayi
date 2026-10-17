// Package delivery orchestrates bounded, at-least-once outbox delivery.
package delivery

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

var ErrUnavailable = errors.New("outbox delivery unavailable")

type Service struct {
	store Store
	sink  Sink
	clock Clock
	scope grants.Scope
}

func New(store Store, sink Sink, clock Clock, scope grants.Scope) (*Service, error) {
	if store == nil || sink == nil || clock == nil || !scope.Valid() {
		return nil, ErrUnavailable
	}
	return &Service{store: store, sink: sink, clock: clock, scope: scope}, nil
}

// Drain leaves failed/abandoned leases retryable. A crash after external delivery
// but before acknowledgement may duplicate an event; consumers deduplicate IDs.
func (s *Service) Drain(ctx context.Context, scope grants.Scope, limit int) (int, error) {
	if !scope.Valid() || scope != s.scope || limit < 1 || limit > 100 {
		return 0, ErrUnavailable
	}
	for n := 0; n < limit; n++ {
		event, ok, err := s.store.ClaimEvent(ctx, scope, s.clock.Now(), time.Minute)
		if err != nil {
			return n, ErrUnavailable
		}
		if !ok {
			return n, nil
		}
		if event.Event.Scope != scope {
			return n, ErrUnavailable
		}
		if err := s.sink.Deliver(ctx, event.Event); err != nil {
			return n, ErrUnavailable
		}
		if err := s.store.CompleteEvent(ctx, event, s.clock.Now()); err != nil {
			return n, ErrUnavailable
		}
	}
	return limit, nil
}
