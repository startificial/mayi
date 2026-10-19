package contract_test

import (
	"context"
	"testing"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/tokens"
)

func fixtureObjects(t *testing.T, f *fixture) grants.ObjectCeiling {
	t.Helper()
	c, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: f.cmd.Caller.Scope, Resource: f.cmd.Resource, Details: []grants.ObjectDetail{{Type: "https://api.example/types/workflow/v1", Identifier: "workflow:123", Actions: []string{"execute"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestObjectRedemptionCannotFallBackToScopeOnlyIssuance(t *testing.T) {
	for _, kind := range []string{tokens.AuthorizationCode, tokens.RefreshToken} {
		for _, position := range []string{"credential", "revision", "current grant"} {
			t.Run(kind+"/"+position, func(t *testing.T) {
				f := newFixture(t, kind)
				objects := fixtureObjects(t, f)
				switch position {
				case "credential":
					c := f.store.state.credentials[f.cmd.CredentialHash]
					c.ObjectBound = true
					f.store.state.credentials[c.Hash] = c
				case "revision":
					s := f.store.state.grant.Revision.Snapshot()
					s.ObjectCeiling = objects
					r, err := grants.NewRevision(s)
					if err != nil {
						t.Fatal(err)
					}
					f.store.state.grant.Revision = r
				case "current grant":
					f.store.state.grant.CurrentObjectCeiling = objects
				}
				r, err := f.service.Redeem(context.Background(), f.cmd)
				assertEmpty(t, r, err, tokens.ErrInvalidCredential)
				if f.signer.calls != 0 || f.material.n != 0 || len(f.store.state.issuances) != 0 || len(f.store.state.audit) != 0 || f.store.state.credentials[f.cmd.CredentialHash].Consumed {
					t.Fatal("unsupported object redemption signed, consumed or issued")
				}
				if position == "credential" && f.store.grantReads != 0 {
					t.Fatal("unsupported credential loaded grant authority unnecessarily")
				}
			})
		}
	}
}

func TestObjectReplayStillRequiresPossessionAndRevokes(t *testing.T) {
	for _, kind := range []string{tokens.AuthorizationCode, tokens.RefreshToken} {
		for _, mode := range []string{"valid", "foreign tenant", "foreign client", "wrong proof"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := newFixture(t, kind)
				c := f.store.state.credentials[f.cmd.CredentialHash]
				c.ObjectBound = true
				c.Consumed = true
				f.store.state.credentials[c.Hash] = c
				switch mode {
				case "foreign tenant":
					f.cmd.Caller.Scope.TenantID = "other"
				case "foreign client":
					f.cmd.Caller.ClientID = "other"
				case "wrong proof":
					f.cmd.Caller.BindingThumbprint = "other-key"
				}
				r, err := f.service.Redeem(context.Background(), f.cmd)
				assertEmpty(t, r, err, tokens.ErrInvalidCredential)
				revoked := f.store.state.grant.Revoked || f.store.state.revokedCodes[c.Hash]
				if revoked != (mode == "valid") || f.signer.calls != 0 || f.material.n != 0 || f.store.grantReads != 0 {
					t.Fatal("object replay bypassed possession or issuance boundary")
				}
			})
		}
	}
}
