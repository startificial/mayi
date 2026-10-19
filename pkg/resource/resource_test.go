package resource_test

import (
	"context"
	"errors"
	"github.com/startificial/mayi/pkg/resource"
	"net/http/httptest"
	"testing"
)

type guard struct{}

func (guard) WithPermission(context.Context, resource.Principal, resource.Request, func(context.Context) error) error {
	panic("canceled request reached permission or payload lookup")
}
func TestSDKPreservesCancellationAndFailsClosed(t *testing.T) {
	client, err := resource.New(resource.Config{Tenant: "a", Issuer: "https://auth.example/t/a", Audience: "https://api.example", IntrospectionEndpoint: "http://127.0.0.1:1/introspect", ClientID: "resource", ClientSecret: "secret", AllowInsecureLoopback: true, Profiles: []resource.Profile{{Type: "https://api.example/types/document/v1", Actions: []resource.Action{{Name: "read", Description: "Read documents"}}}}}, guard{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = client.WithAccess(ctx, "token", resource.Request{Type: "https://api.example/types/document/v1", Identifier: "123", Action: "read", Permission: "read"}, func(context.Context, resource.Principal) error { t.Fatal("canceled payload load"); return nil })
	if !errors.Is(err, context.Canceled) || !errors.Is(err, resource.ErrUnavailable) {
		t.Fatal("cancellation classification lost", err)
	}
}

func TestResourceCredentialsComeOnlyFromOneAuthorizationHeader(t *testing.T) {
	for _, mode := range []string{"missing", "query", "duplicate", "body only", "wrong scheme", "bound without proof", "duplicate proof", "bearer with proof"} {
		t.Run(mode, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://api.example/documents/123", nil)
			r.Header.Set("Authorization", "Bearer access")
			switch mode {
			case "missing", "body only":
				r.Header.Del("Authorization")
			case "query":
				r.URL.RawQuery = "access_token=access"
			case "duplicate":
				r.Header.Add("Authorization", "Bearer other")
			case "wrong scheme":
				r.Header.Set("Authorization", "Basic access")
			case "bound without proof":
				r.Header.Set("Authorization", "DPoP access")
			case "duplicate proof":
				r.Header.Set("Authorization", "DPoP access")
				r.Header.Add("DPoP", "one")
				r.Header.Add("DPoP", "two")
			case "bearer with proof":
				r.Header.Set("DPoP", "proof")
			}
			if token, err := resource.HeaderToken(r); token != "" || !errors.Is(err, resource.ErrDenied) {
				t.Fatal("invalid credential location accepted")
			}
		})
	}
	r := httptest.NewRequest("GET", "https://api.example/documents/123", nil)
	r.Header.Set("Authorization", "Bearer access")
	if token, err := resource.HeaderToken(r); err != nil || token != "access" {
		t.Fatal("valid header denied")
	}
}
