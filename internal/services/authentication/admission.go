package authentication

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
)

var ErrLimited = errors.New("request budget exhausted")

type LimitError struct{ RetryAfterSeconds int }

func (e *LimitError) Error() string { return "request budget exhausted" }
func (e *LimitError) Unwrap() error { return ErrLimited }

// Budget identifies one finite shared counter. Only the persistence port chooses
// authoritative time and atomically consumes capacity; replicas share no cache.
type Budget struct {
	Operation, Dimension, Key string
	Limit, WindowSeconds      int
}
type BudgetRule struct {
	Operation, Dimension string
	Limit, WindowSeconds int
}
type Admission struct {
	store AdmissionStore
	rules map[[2]string]BudgetRule
}

func DefaultBudgetRules() []BudgetRule {
	result := []BudgetRule{}
	for _, op := range []string{"login", "token", "introspection"} {
		for _, dim := range []string{"ip", "client", "user"} {
			limit := 120
			if dim == "ip" {
				limit = 600
			}
			if op == "login" {
				limit = 30
				if dim == "ip" {
					limit = 120
				}
			}
			if op == "introspection" {
				limit = 6000
			}
			result = append(result, BudgetRule{Operation: op, Dimension: dim, Limit: limit, WindowSeconds: 60})
		}
	}
	return result
}
func NewAdmission(store AdmissionStore, rules []BudgetRule) (*Admission, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	parsed, err := budgetRules(rules)
	if err != nil {
		return nil, err
	}
	return &Admission{store: store, rules: parsed}, nil
}
func ValidBudgetRules(rules []BudgetRule) bool { _, err := budgetRules(rules); return err == nil }
func budgetRules(rules []BudgetRule) (map[[2]string]BudgetRule, error) {
	if len(rules) != 9 {
		return nil, ErrUnavailable
	}
	result := map[[2]string]BudgetRule{}
	for _, r := range rules {
		if r.Operation != "login" && r.Operation != "token" && r.Operation != "introspection" || r.Dimension != "ip" && r.Dimension != "client" && r.Dimension != "user" || r.Limit < 1 || r.Limit > 1000000 || r.WindowSeconds < 1 || r.WindowSeconds > 3600 {
			return nil, ErrUnavailable
		}
		key := [2]string{r.Operation, r.Dimension}
		if _, ok := result[key]; ok {
			return nil, ErrUnavailable
		}
		result[key] = r
	}
	return result, nil
}
func (a *Admission) Check(ctx context.Context, scope grants.Scope, operation, dimension, key string) error {
	return a.CheckUsing(ctx, a.store, scope, operation, dimension, key)
}
func (a *Admission) CheckUsing(ctx context.Context, store AdmissionStore, scope grants.Scope, operation, dimension, key string) error {
	if store == nil {
		return ErrUnavailable
	}
	rule, ok := a.rules[[2]string{operation, dimension}]
	if !ok || !scope.Valid() || key == "" || len(key) > 2304 {
		return ErrDenied
	}
	for _, c := range key {
		if c < 0x20 || c == 0x7f {
			return ErrDenied
		}
	}
	allowed, err := store.ConsumeBudget(ctx, scope, Budget{Operation: operation, Dimension: dimension, Key: key, Limit: rule.Limit, WindowSeconds: rule.WindowSeconds})
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if !allowed {
		return &LimitError{RetryAfterSeconds: rule.WindowSeconds}
	}
	return nil
}
