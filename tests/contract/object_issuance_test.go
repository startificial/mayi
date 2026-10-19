package contract_test

import (
	"context"
	"github.com/startificial/mayi/internal/domain/resources"
	"testing"
	"time"

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

func completeObjectFixture(t *testing.T, kind string) *fixture {
	t.Helper()
	f := newFixture(t, kind)
	spec := f.store.state.grant.Revision.Snapshot()
	var err error
	spec.ObjectCeiling, err = grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: spec.Scope, Resource: spec.Resource, Details: []grants.ObjectDetail{
		{Type: "https://api.example/types/workflow/v1", Identifier: "workflow:123", Actions: []string{"execute", "edit"}},
		{Type: "https://api.example/types/workflow/v1", Identifier: "workflow:124", Actions: []string{"execute"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	f.store.state.grant.Revision, err = grants.NewRevision(spec)
	if err != nil {
		t.Fatal(err)
	}
	f.store.state.grant.CurrentObjectCeiling = spec.ObjectCeiling
	profile, err := resources.NewObjectProfile(resources.ObjectProfileSpec{Scope: spec.Scope, Resource: spec.Resource, Type: "https://api.example/types/workflow/v1", Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "execute", Description: "Run workflow"}, {Name: "edit", Description: "Edit workflow"}}})
	if err != nil {
		t.Fatal(err)
	}
	f.store.state.grant.ObjectProfiles = []resources.ObjectProfile{profile}
	f.store.state.grant.MaxAccessTokenSeconds = 60
	c := f.store.state.credentials[f.cmd.CredentialHash]
	c.ObjectBound = true
	f.store.state.credentials[c.Hash] = c
	f.store.state.credentialObjects = map[string]grants.ObjectCeiling{c.Hash: spec.ObjectCeiling}
	return f
}

func TestObjectRedemptionPreservesExactTuplesAndRefreshCannotRegainAuthority(t *testing.T) {
	for _, kind := range []string{tokens.AuthorizationCode, tokens.RefreshToken} {
		t.Run(kind, func(t *testing.T) {
			f := completeObjectFixture(t, kind)
			f.cmd.Objects = []grants.ObjectDetail{{Type: "https://api.example/types/workflow/v1", Identifier: "workflow:123", Actions: []string{"execute"}}}
			r, err := f.service.Redeem(context.Background(), f.cmd)
			if err != nil {
				t.Fatal(err)
			}
			ceiling := r.Claims.ObjectCeiling
			if len(ceiling.Snapshot().Details) != 1 || !ceiling.Permits(f.cmd.Caller.Scope, f.cmd.Resource, f.cmd.Objects[0].Type, "workflow:123", "execute") || ceiling.Permits(f.cmd.Caller.Scope, f.cmd.Resource, f.cmd.Objects[0].Type, "workflow:124", "execute") || ceiling.Permits(f.cmd.Caller.Scope, f.cmd.Resource, f.cmd.Objects[0].Type, "workflow:123", "edit") || !r.Claims.ExpiresAt.Equal(f.now.Add(time.Minute)) || !f.store.state.issuances[0].Claims.ObjectCeiling.Equal(ceiling) {
				t.Fatal("authority/lifetime widened", r.Claims)
			}
			if kind == tokens.RefreshToken {
				f.cmd.CredentialHash = f.store.state.issuances[0].RefreshHash
				f.cmd.Objects[0].Actions = []string{"edit"}
				denied, err := f.service.Redeem(context.Background(), f.cmd)
				assertEmpty(t, denied, err, tokens.ErrInvalidCredential)
				if f.signer.calls != 1 {
					t.Fatal("expanded refresh reached signer")
				}
				f.cmd.Objects = nil
				next, err := f.service.Redeem(context.Background(), f.cmd)
				if err != nil || !next.Claims.ObjectCeiling.Equal(ceiling) {
					t.Fatal("omission regained authority", err)
				}
			}
		})
	}
}

func TestObjectRedemptionDeniesInvalidAuthorityBeforeEntropyAndSigning(t *testing.T) {
	for _, mode := range []string{"empty request", "unknown action", "unapproved object", "tuple recombination", "missing profile", "missing credential ceiling", "foreign ceiling", "permission removed", "revoked", "policy changed", "commit failure"} {
		t.Run(mode, func(t *testing.T) {
			f := completeObjectFixture(t, tokens.RefreshToken)
			target := grants.ObjectDetail{Type: "https://api.example/types/workflow/v1", Identifier: "workflow:123", Actions: []string{"execute"}}
			f.cmd.Objects = []grants.ObjectDetail{target}
			switch mode {
			case "empty request":
				f.cmd.Objects = []grants.ObjectDetail{}
			case "unknown action":
				f.cmd.Objects[0].Actions = []string{"admin"}
			case "unapproved object":
				f.cmd.Objects[0].Identifier = "workflow:125"
			case "tuple recombination":
				f.cmd.Objects[0].Identifier = "workflow:124"
				f.cmd.Objects[0].Actions = []string{"edit"}
			case "missing profile":
				f.store.state.grant.ObjectProfiles = nil
			case "missing credential ceiling":
				delete(f.store.state.credentialObjects, f.cmd.CredentialHash)
			case "foreign ceiling":
				spec := f.store.state.credentialObjects[f.cmd.CredentialHash].Snapshot()
				spec.Scope.TenantID = "other"
				c, err := grants.NewObjectCeiling(spec)
				if err != nil {
					t.Fatal(err)
				}
				f.store.state.credentialObjects[f.cmd.CredentialHash] = c
			case "permission removed":
				spec := f.store.state.grant.CurrentObjectCeiling.Snapshot()
				spec.Details[0].Actions = []string{"edit"}
				c, err := grants.NewObjectCeiling(spec)
				if err != nil {
					t.Fatal(err)
				}
				f.store.state.grant.CurrentObjectCeiling = c
			case "revoked":
				f.store.state.grant.Revoked = true
			case "policy changed":
				f.store.state.grant.PolicyVersion++
			case "commit failure":
				f.store.commitFail = true
			}
			r, err := f.service.Redeem(context.Background(), f.cmd)
			want := tokens.ErrInvalidCredential
			if mode == "commit failure" {
				want = tokens.ErrUnavailable
			}
			assertEmpty(t, r, err, want)
			if f.store.state.credentials[f.cmd.CredentialHash].Consumed || len(f.store.state.issuances) != 0 {
				t.Fatal("denial committed authority")
			}
			if mode != "commit failure" && (f.signer.calls != 0 || f.material.n != 0) {
				t.Fatal("denial reached effects")
			}
		})
	}
}
