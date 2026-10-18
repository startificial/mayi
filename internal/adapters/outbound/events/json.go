// Package events implements credential-free audit output for an operator-owned
// collector. Delivery is at least once; this is not a durable remote SIEM.
package events

import (
	"context"
	"encoding/json"
	"github.com/startificial/mayi/internal/domain/audit"
	"github.com/startificial/mayi/internal/services/delivery"
	"io"
	"time"
)

var _ delivery.Sink = (*JSON)(nil)

type JSON struct {
	writer  io.Writer
	writing chan struct{}
}

func New(writer io.Writer) (*JSON, error) {
	if writer == nil {
		return nil, delivery.ErrUnavailable
	}
	return &JSON{writer: writer, writing: make(chan struct{}, 1)}, nil
}
func (s *JSON) Deliver(ctx context.Context, e audit.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	value := struct {
		SchemaVersion int    `json:"schema_version"`
		ID            int64  `json:"event_id"`
		Tenant        string `json:"tenant_id"`
		Issuer        string `json:"issuer"`
		Type          string `json:"type"`
		Actor         string `json:"actor"`
		Object        string `json:"object"`
		GrantID       string `json:"grant_id,omitempty"`
		IssuanceID    string `json:"issuance_id,omitempty"`
		Time          string `json:"time"`
	}{1, e.ID, e.Scope.TenantID, e.Scope.Issuer, e.Type, e.Actor, e.Object, e.GrantID, e.IssuanceID, e.OccurredAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")}
	// io.Writer has no cancellation contract. Bound the caller's entire wait,
	// including serialization behind an earlier write. At most one underlying
	// write exists per sink; its slot is held until it actually finishes.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case s.writing <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-s.writing
		return err
	}
	done := make(chan error, 1)
	go func() {
		defer func() { <-s.writing }()
		done <- json.NewEncoder(s.writer).Encode(value)
	}()
	select {
	case err := <-done:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
