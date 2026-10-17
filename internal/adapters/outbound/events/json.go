// Package events implements credential-free audit output for an operator-owned
// collector. Delivery is at least once; this is not a durable remote SIEM.
package events

import (
	"context"
	"encoding/json"
	"github.com/startificial/mayi/internal/domain/audit"
	"github.com/startificial/mayi/internal/services/delivery"
	"io"
	"sync"
)

var _ delivery.Sink = (*JSON)(nil)

type JSON struct {
	writer io.Writer
	mu     sync.Mutex
}

func New(writer io.Writer) (*JSON, error) {
	if writer == nil {
		return nil, delivery.ErrUnavailable
	}
	return &JSON{writer: writer}, nil
}
func (s *JSON) Deliver(ctx context.Context, e audit.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	value := struct {
		ID     int64  `json:"event_id"`
		Tenant string `json:"tenant_id"`
		Issuer string `json:"issuer"`
		Type   string `json:"type"`
		Actor  string `json:"actor"`
		Object string `json:"object"`
		Time   string `json:"time"`
	}{e.ID, e.Scope.TenantID, e.Scope.Issuer, e.Type, e.Actor, e.Object, e.OccurredAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")}
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.NewEncoder(s.writer).Encode(value)
}
