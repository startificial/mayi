package authentication_test

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authentication"
	"testing"
)

type budgetStore struct {
	calls   int
	allowed bool
	err     error
}

func (s *budgetStore) ConsumeBudget(context.Context, grants.Scope, authentication.Budget) (bool, error) {
	s.calls++
	return s.allowed, s.err
}
func TestAdmissionValidatesBeforeStateAndFailsClosed(t *testing.T) {
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	store := &budgetStore{allowed: true}
	service, err := authentication.NewAdmission(store, authentication.DefaultBudgetRules())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "bad\nkey"} {
		if err := service.Check(context.Background(), scope, "token", "client", key); !errors.Is(err, authentication.ErrDenied) {
			t.Fatal(err)
		}
	}
	if err := service.Check(context.Background(), grants.Scope{}, "token", "client", "web"); !errors.Is(err, authentication.ErrDenied) {
		t.Fatal(err)
	}
	if store.calls != 0 {
		t.Fatal("invalid admission reached state")
	}
	if err := service.Check(context.Background(), scope, "token", "client", "web"); err != nil {
		t.Fatal(err)
	}
	store.allowed = false
	var limited *authentication.LimitError
	if err := service.Check(context.Background(), scope, "token", "client", "web"); !errors.As(err, &limited) || limited.RetryAfterSeconds != 60 {
		t.Fatal(err)
	}
	store.err = errors.New("database failure")
	if err := service.Check(context.Background(), scope, "token", "client", "web"); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatal("unavailable authority allowed a request", err)
	}
	for _, mode := range []string{"missing", "duplicate", "unbounded", "zero window"} {
		rules := authentication.DefaultBudgetRules()
		switch mode {
		case "missing":
			rules = rules[:8]
		case "duplicate":
			rules[1] = rules[0]
		case "unbounded":
			rules[0].Limit = 1000001
		case "zero window":
			rules[0].WindowSeconds = 0
		}
		if authentication.ValidBudgetRules(rules) {
			t.Fatal("invalid configuration admitted", mode)
		}
	}
}
