package events_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/adapters/outbound/events"
	"github.com/startificial/mayi/internal/domain/audit"
	"github.com/startificial/mayi/internal/domain/grants"
)

func TestJSONPreservesNonSecretCorrelation(t *testing.T) {
	var output bytes.Buffer
	sink, _ := events.New(&output)
	e := audit.Event{ID: 1, Scope: grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}, Type: "token_issued", GrantID: "grant-1", IssuanceID: "issuance-1", OccurredAt: time.Unix(1, 0)}
	if err := sink.Deliver(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if json.Unmarshal(output.Bytes(), &wire) != nil || wire["grant_id"] != e.GrantID || wire["issuance_id"] != e.IssuanceID || wire["schema_version"] != float64(1) {
		t.Fatal("incomplete or unexpected envelope", output.String())
	}
	for _, field := range []string{"credential_hash", "token", "private_key"} {
		if _, ok := wire[field]; ok {
			t.Fatal("sensitive field exported", field)
		}
	}
}

type stalledWriter struct {
	started chan struct{}
	release chan struct{}
	writes  atomic.Int32
}

func (w *stalledWriter) Write(b []byte) (int, error) {
	w.writes.Add(1)
	close(w.started)
	<-w.release
	return len(b), nil
}
func TestJSONCancellationBoundsWaitAndUnderlyingWrites(t *testing.T) {
	w := &stalledWriter{started: make(chan struct{}), release: make(chan struct{})}
	defer close(w.release)
	sink, _ := events.New(w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sink.Deliver(ctx, audit.Event{}) }()
	<-w.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation blocked")
	}
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		err := sink.Deliver(ctx, audit.Event{})
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	}
	if w.writes.Load() != 1 {
		t.Fatal("created more underlying writes while output was stuck")
	}
}
func TestJSONBoundsUncancelledOutputWait(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	sink, _ := events.New(writer)
	started := time.Now()
	err := sink.Deliver(context.Background(), audit.Event{})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 7*time.Second {
		t.Fatal("output wait was not bounded", err)
	}
}
func TestJSONPropagatesWriteFailure(t *testing.T) {
	reader, writer := io.Pipe()
	reader.Close()
	defer writer.Close()
	sink, _ := events.New(writer)
	if err := sink.Deliver(context.Background(), audit.Event{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
