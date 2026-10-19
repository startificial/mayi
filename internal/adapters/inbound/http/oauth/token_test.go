package oauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/ory/fosite"
	"github.com/startificial/mayi/internal/services/tokens"
)

func TestTokenDetailsBoundaryPreservesOmissionAndRejectsAmbiguity(t *testing.T) {
	scope := rarProfile(t).Snapshot().Scope
	for _, tc := range []struct {
		name, raw      string
		valid, omitted bool
	}{
		{"omitted", "", true, true},
		{"explicit", "[" + rarEntry("123", "read") + "]", true, false},
		{"empty", "[]", false, false},
		{"null", "null", false, false},
		{"duplicate", strings.Replace("["+rarEntry("123", "read")+"]", `"identifier":"123"`, `"identifier":"123","identifier":"124"`, 1), false, false},
		{"wildcard", "[" + rarEntry("*", "read") + "]", false, false},
		{"foreign audience", strings.Replace("["+rarEntry("123", "read")+"]", "https://api.example/documents", "https://other.example/documents", 1), false, false},
		{"oversized", strings.Repeat(" ", MaxAuthorizationDetailsBytes+1), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fosite.NewAccessRequest(&fosite.DefaultSession{})
			r.Client = &fosite.DefaultClient{ID: "web", Public: true}
			r.GrantTypes = fosite.Arguments{tokens.RefreshToken}
			r.Form = url.Values{"resource": {"https://api.example/documents"}, "refresh_token": {"synthetic-secret"}}
			if !tc.omitted {
				r.Form["authorization_details"] = []string{tc.raw}
			}
			h := &TokenHandler{scope: scope}
			ctx := WithCaller(context.Background(), tokens.Caller{Scope: scope, ClientID: "web"})
			cmd, err := h.command(ctx, r)
			if tc.valid {
				if err != nil || (cmd.Objects == nil) != tc.omitted {
					t.Fatal("boundary lost omission or valid details", err)
				}
			} else if !errors.Is(err, fosite.ErrInvalidRequest) || cmd.CredentialHash != "" {
				t.Fatal("malformed details reached service command", err)
			}
		})
	}
}
