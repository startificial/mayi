package health

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"testing"
)

type fake struct {
	databaseErr, keyErr, signerErr error
	keyReads, signatures           int
}

func (f *fake) CheckHealth(context.Context) error { return f.databaseErr }
func (f *fake) ActiveSigningKey(context.Context, grants.Scope) (int, error) {
	f.keyReads++
	return 1, f.keyErr
}
func (f *fake) Check(context.Context, grants.Scope, int) error { f.signatures++; return f.signerErr }
func TestReadinessFailsClosedAndDoesNotProbePastFailure(t *testing.T) {
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	for _, mode := range []string{"database", "key", "signer", "ready"} {
		t.Run(mode, func(t *testing.T) {
			f := &fake{}
			switch mode {
			case "database":
				f.databaseErr = ErrUnavailable
			case "key":
				f.keyErr = ErrUnavailable
			case "signer":
				f.signerErr = ErrUnavailable
			}
			s, _ := New(f, f, []TenantSigner{{Scope: scope, Signer: f}})
			err := s.Ready(context.Background())
			if mode == "ready" && err != nil || mode != "ready" && err == nil {
				t.Fatal("incorrect readiness")
			}
			if mode == "database" && (f.keyReads > 0 || f.signatures > 0) || mode == "key" && f.signatures > 0 {
				t.Fatal("probed after dependency failure")
			}
		})
	}
}
