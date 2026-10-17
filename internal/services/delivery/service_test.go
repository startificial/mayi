package delivery

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/audit"
	"github.com/startificial/mayi/internal/domain/grants"
	"testing"
	"time"
)

type fake struct {
	delivery                       audit.Delivery
	claimErr, sinkErr, completeErr error
	claimed, delivered, completed  int
}

func (f *fake) ClaimEvent(context.Context, grants.Scope, time.Time, time.Duration) (audit.Delivery, bool, error) {
	f.claimed++
	return f.delivery, true, f.claimErr
}
func (f *fake) CompleteEvent(context.Context, audit.Delivery, time.Time) error {
	f.completed++
	return f.completeErr
}
func (f *fake) Deliver(context.Context, audit.Event) error { f.delivered++; return f.sinkErr }
func (f *fake) Now() time.Time                             { return time.Unix(100, 0) }
func TestDeliveryDoesNotAcknowledgeFailuresOrForeignTenant(t *testing.T) {
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	for _, mode := range []string{"claim failure", "sink failure", "foreign tenant", "ack failure", "success"} {
		t.Run(mode, func(t *testing.T) {
			f := &fake{delivery: audit.Delivery{Event: audit.Event{Scope: scope, ID: 1}, Attempt: 1}}
			failure := errors.New("failure")
			switch mode {
			case "claim failure":
				f.claimErr = failure
			case "sink failure":
				f.sinkErr = failure
			case "foreign tenant":
				f.delivery.Event.Scope.TenantID = "b"
			case "ack failure":
				f.completeErr = failure
			}
			s, _ := New(f, f, f, scope)
			_, err := s.Drain(context.Background(), scope, 1)
			if mode == "success" {
				if err != nil || f.completed != 1 || f.delivered != 1 {
					t.Fatal("valid delivery failed")
				}
			} else if err == nil {
				t.Fatal("failure not propagated")
			}
			if mode == "sink failure" && f.completed != 0 {
				t.Fatal("failed delivery acknowledged")
			}
			if (mode == "claim failure" || mode == "foreign tenant") && (f.delivered != 0 || f.completed != 0) {
				t.Fatal("invalid delivery escaped")
			}
		})
	}
}
func TestWorkerRejectsUnconfiguredTenantBeforeClaim(t *testing.T) {
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	f := &fake{}
	s, _ := New(f, f, f, scope)
	foreign := scope
	foreign.TenantID = "b"
	if _, err := s.Drain(context.Background(), foreign, 1); err == nil || f.claimed != 0 || f.delivered != 0 || f.completed != 0 {
		t.Fatal("foreign worker operation accepted")
	}
}
