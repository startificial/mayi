package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/authorization"
)

func TestP2PushedWireBindsMixedTypesWithoutEnablingConsent(t *testing.T) {
	e, svc, base, browser := setupAuthorization(t)
	ctx := context.Background()
	management, actor, spec := profileManagement(t, e, base.TenantIssuer)
	actor.Permissions = []string{"resources:write", "clients:write"}
	if err := management.RegisterObjectProfile(ctx, actor, actor.Scope, "api", spec); err != nil {
		t.Fatal(err)
	}
	client := clients.Client{ID: "mixed-web", Name: "Mixed types client", Resources: []string{"api"}, RedirectURIs: []string{base.RedirectURI}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1", spec.Type}, Enabled: true, AccessTokenSeconds: 300}
	if err := management.CreateClient(ctx, actor, actor.Scope, client); err != nil {
		t.Fatal(err)
	}
	var profiles []resources.ObjectProfile
	err := e.store.RunAuthorization(ctx, actor.Scope, func(tx authorization.Transaction) error {
		current, err := tx.Registration(ctx, client.ID, base.ResourceURI)
		if err == nil {
			profiles = current.ObjectProfiles
		}
		return err
	})
	if err != nil || len(profiles) != 2 {
		t.Fatal("current registration projection", err)
	}
	rawDetails := `[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"123","actions":["read"]},{"type":"https://api.example/types/workflow/v1","locations":["https://api.example"],"identifier":"123","actions":["execute"]}]`
	form := url.Values{"client_id": {client.ID}, "response_type": {"code"}, "redirect_uri": {base.RedirectURI}, "resource": {base.ResourceURI}, "scope": {"read"}, "state": {"original&state=123%2F+same"}, "code_challenge": {base.PKCEChallenge}, "code_challenge_method": {"S256"}, "authorization_details": {rawDetails}}
	request, err := oauth.DecodePushedRequest(form.Encode(), actor.Scope, profiles...)
	if err != nil {
		t.Fatal(err)
	}
	pushed, err := svc.Push(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := oauth.EncodePushedResponse(pushed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &response); err != nil || response.ExpiresIn < 1 || response.ExpiresIn > 90 {
		t.Fatal("invalid response", err)
	}
	query := url.Values{"client_id": {client.ID}, "request_uri": {response.RequestURI}}
	proof, err := oauth.DecodePushedAuthorization(query.Encode(), actor.Scope, browser.BrowserBindingHash)
	if err != nil || proof.ReferenceHash != secretHash(pushed.Reference) {
		t.Fatal("wire reference did not match persisted hash", err)
	}
	// A well-formed reference for another declared client remains a generic
	// service denial, with no reference consumption or workflow created.
	wrong := proof
	wrong.ClientID = "web"
	if out, err := svc.BeginPushed(ctx, wrong); !errors.Is(err, authorization.ErrDenied) || out.Handle != "" {
		t.Fatal("swapped client acquired workflow", err)
	}
	query.Set("state", "replacement-state")
	if _, err := oauth.DecodePushedAuthorization(query.Encode(), actor.Scope, browser.BrowserBindingHash); !errors.Is(err, oauth.ErrInvalidPushedRequest) {
		t.Fatal("front-channel request replacement accepted", err)
	}
	begun, err := svc.BeginPushed(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	var exact bool
	if err := e.admin.QueryRow(ctx, `SELECT p.object_ceiling=w.object_ceiling AND p.client_state=w.client_state AND p.redirect_uri=w.redirect_uri AND p.pkce_challenge=w.pkce_challenge AND w.client_id=$3 AND w.client_state=$4 AND jsonb_array_length(w.object_ceiling->'details')=2
 FROM mayi.pushed_requests p JOIN mayi.authorization_transactions w ON w.tenant_id=p.tenant_id AND w.handle_hash=p.authorization_hash AND w.pushed_request_hash=p.reference_hash WHERE p.tenant_id='a' AND p.reference_hash=$1 AND w.handle_hash=$2`, proof.ReferenceHash, secretHash(begun.Handle), client.ID, form.Get("state")).Scan(&exact); err != nil || !exact {
		t.Fatal("wire request lost exact stored correlation", err)
	}
	if out, err := svc.BeginPushed(ctx, proof); !errors.Is(err, authorization.ErrDenied) || out.Handle != "" {
		t.Fatal("wire reference replay succeeded", err)
	}
	browser.AuthorizationHash, browser.CSRFHash = secretHash(begun.Handle), secretHash(begun.CSRFToken)
	if view, err := svc.PrepareConsent(ctx, browser); !errors.Is(err, authorization.ErrDenied) || view.ClientID != "" {
		t.Fatal("wire codec enabled unreviewed object consent", err)
	}
	if out, err := svc.Decide(ctx, authorization.Decision{Proof: browser, Approve: true}); !errors.Is(err, authorization.ErrDenied) || out.Code != "" {
		t.Fatal("wire codec enabled object credential issuance", err)
	}
}

func TestP2PushedWireRegistrationIsRecheckedByService(t *testing.T) {
	e, svc, base, _ := setupAuthorization(t)
	ctx := context.Background()
	var profiles []resources.ObjectProfile
	if err := e.store.RunAuthorization(ctx, base.TenantIssuer, func(tx authorization.Transaction) error {
		current, err := tx.Registration(ctx, base.ClientID, base.ResourceURI)
		profiles = current.ObjectProfiles
		return err
	}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"client_id": {base.ClientID}, "response_type": {"code"}, "redirect_uri": {base.RedirectURI}, "resource": {base.ResourceURI}, "scope": {"read"}, "state": {"unpredictable-state-at-least-16"}, "code_challenge": {base.PKCEChallenge}, "code_challenge_method": {"S256"}, "authorization_details": {`[{"type":"https://api.example/types/fixture/v1","locations":["https://api.example"],"identifier":"123","actions":["read"]}]`}}
	request, err := oauth.DecodePushedRequest(form.Encode(), base.TenantIssuer, profiles...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `BEGIN; SELECT tenant_id FROM mayi.tenants WHERE tenant_id='a' FOR UPDATE; UPDATE mayi.clients SET enabled=false WHERE tenant_id='a' AND client_id='web'; COMMIT`); err != nil {
		t.Fatal(err)
	}
	if out, err := svc.Push(ctx, request); !errors.Is(err, authorization.ErrInvalid) || out.Reference != "" {
		t.Fatal("stale wire vocabulary became authority", err)
	}
	var pushed, audits int
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.pushed_requests),(SELECT count(*) FROM mayi.audit_events WHERE event_type='authorization_pushed')`).Scan(&pushed, &audits); err != nil || pushed != 0 || audits != 0 {
		t.Fatal("stale registration created request state", pushed, audits, err)
	}
}
