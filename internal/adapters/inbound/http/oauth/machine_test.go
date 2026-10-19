package oauth

import (
	"context"
	"errors"
	"github.com/ory/fosite"
	"testing"
)

func TestMachineResponseIgnoresOtherHandlersGrants(t *testing.T) {
	handler := &machineHandler{}
	for _, grant := range []string{"authorization_code", "refresh_token", "unsupported"} {
		request := fosite.NewAccessRequest(&fosite.DefaultSession{})
		request.GrantTypes = fosite.Arguments{grant}
		if err := handler.PopulateTokenEndpointResponse(context.Background(), request, fosite.NewAccessResponse()); !errors.Is(err, fosite.ErrUnknownRequest) {
			t.Fatal("unrelated response handler ran", grant, err)
		}
	}
}
