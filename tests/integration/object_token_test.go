package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/app"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/authorization"
	"github.com/startificial/mayi/internal/services/tokens"
)

func TestP2ApprovedObjectCodeCarriesExactDetailsThroughFositeSigningAndPersistence(t *testing.T) {
	// Obtain an independent real Transit signer, then rebuild the application
	// schema through the actual PAR/resource-consent fixture. The key is external
	// to PostgreSQL and remains non-exportable throughout both fixtures.
	key := setup(t).signer
	e, authority, proof := postgresConsentFixture(t)
	ctx := context.Background()
	consent, err := app.NewObjectAuthorization(e.store, clock{}, authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consent.PrepareConsent(ctx, proof); err != nil {
		t.Fatal(err)
	}
	approved, err := consent.Decide(ctx, authorization.Decision{Proof: proof, Approve: true})
	if err != nil {
		t.Fatal(err)
	}
	service, err := app.NewIssuance(e.store, clock{}, key, cryptoadapter.NewMaterialSource(), e.store, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewTokenHandler(proof.TenantIssuer, service)
	if err != nil {
		t.Fatal(err)
	}
	config := &fosite.Config{}
	config.TokenEndpointHandlers.Append(handler)
	registry := storage.NewMemoryStore()
	registry.Clients["web"] = &fosite.DefaultClient{ID: "web", Public: true, GrantTypes: []string{tokens.AuthorizationCode}, Scopes: []string{"read"}}
	provider := fosite.NewOAuth2Provider(registry, config)
	details := `[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"workflow:123","actions":["read"]}]`
	form := url.Values{"grant_type": {tokens.AuthorizationCode}, "client_id": {"web"}, "scope": {"read"}, "resource": {"https://api.example"}, "code": {approved.Code}, "code_verifier": {verifier}, "redirect_uri": {approved.RedirectURI}, "authorization_details": {details}}
	ctx = oauth.WithCaller(ctx, tokens.Caller{Scope: proof.TenantIssuer, ClientID: "web"})
	redeem := func() (fosite.AccessResponder, error) {
		wire := httptest.NewRequest(http.MethodPost, proof.TenantIssuer.Issuer+"/token", strings.NewReader(form.Encode()))
		wire.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r, err := provider.NewAccessRequest(ctx, wire, &fosite.DefaultSession{})
		if err != nil {
			return nil, err
		}
		return provider.NewAccessResponse(ctx, r)
	}
	// A wire attempt to add an unapproved object must not consume the code.
	form.Set("authorization_details", strings.Replace(details, "workflow:123", "workflow:124", 1))
	if _, err := redeem(); !errors.Is(err, fosite.ErrInvalidGrant) {
		t.Fatal("expanded details accepted", err)
	}
	form.Set("authorization_details", details)
	response, err := redeem()
	if err != nil {
		t.Fatal("object code redemption", err)
	}
	raw, ok := response.GetExtra("authorization_details").(json.RawMessage)
	if !ok {
		t.Fatal("response omitted standard object authority")
	}
	parsed, err := jwt.ParseSigned(response.GetAccessToken(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var keys jose.JSONWebKeySet
	public, err := key.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(public, &keys); err != nil {
		t.Fatal(err)
	}
	var signed struct {
		Details json.RawMessage `json:"authorization_details"`
		ID      string          `json:"jti"`
	}
	if err := parsed.Claims(keys.Keys[0].Key, &signed); err != nil {
		t.Fatal("signature validation", err)
	}
	profile, err := resources.NewObjectProfile(resources.ObjectProfileSpec{Scope: proof.TenantIssuer, Resource: "https://api.example", Type: "https://api.example/types/fixture/v1", Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "read", Description: "Read items"}, {Name: "write", Description: "Write items"}}})
	if err != nil {
		t.Fatal(err)
	}
	signedCeiling, err := oauth.DecodeAuthorizationDetails(string(signed.Details), profile)
	if err != nil {
		t.Fatal("JWT RAR invalid", err)
	}
	responseCeiling, err := oauth.DecodeAuthorizationDetails(string(raw), profile)
	if err != nil || !responseCeiling.Equal(signedCeiling) || !signedCeiling.Permits(proof.TenantIssuer, "https://api.example", profile.Snapshot().Type, "workflow:123", "read") || signedCeiling.Permits(proof.TenantIssuer, "https://api.example", profile.Snapshot().Type, "workflow:124", "read") || signedCeiling.Permits(proof.TenantIssuer, "https://api.example", profile.Snapshot().Type, "workflow:123", "write") {
		t.Fatal("signed/response authority changed", err)
	}
	var exact bool
	if err := e.admin.QueryRow(ctx, `SELECT i.object_ceiling=c.object_ceiling AND i.object_ceiling=r.object_ceiling FROM mayi.issuances i JOIN mayi.credentials c ON c.tenant_id=i.tenant_id AND c.hash=i.source_credential JOIN mayi.grant_revisions r ON r.tenant_id=i.tenant_id AND r.grant_id=i.grant_id AND r.revision=i.revision WHERE i.tenant_id='a' AND i.issuance_id=$1`, signed.ID).Scan(&exact); err != nil || !exact {
		t.Fatal("persisted authority differs", err)
	}
	if _, err := redeem(); !errors.Is(err, fosite.ErrInvalidGrant) {
		t.Fatal("object code replay accepted", err)
	}
	var revoked bool
	if err := e.admin.QueryRow(ctx, `SELECT revoked FROM mayi.issuances WHERE tenant_id='a' AND issuance_id=$1`, signed.ID).Scan(&revoked); err != nil || !revoked {
		t.Fatal("replay did not revoke object issuance", err)
	}
}
