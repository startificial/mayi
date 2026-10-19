package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/authorization"
)

func objectClient(id string) clients.Client {
	return clients.Client{ID: id, Name: "RAR client", RedirectURIs: []string{"https://app.example/cb?provider=mayi"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}, AccessTokenSeconds: 300, Enabled: true}
}

func TestP2ClientTypesRollbackAndConcurrentCreation(t *testing.T) {
	e, _, request, _ := setupAuthorization(t)
	s, actor, _ := profileManagement(t, e, request.TenantIssuer)
	actor.Permissions = []string{"clients:write", "clients:read"}
	ctx := context.Background()
	client := objectClient("rar-client")
	if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_client_outbox() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test outbox failure'; END$$; CREATE TRIGGER fail_client BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_client_outbox()`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(ctx, actor, actor.Scope, client); !errors.Is(err, administration.ErrUnavailable) {
		t.Fatal("uncommitted type registration acknowledged", err)
	}
	var roots, relations, types, audits int
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.clients WHERE client_id=$1),(SELECT count(*) FROM mayi.client_resources WHERE client_id=$1),(SELECT count(*) FROM mayi.client_object_types WHERE client_id=$1),(SELECT count(*) FROM mayi.audit_events WHERE event_type='client_created')`, client.ID).Scan(&roots, &relations, &types, &audits); err != nil || roots != 0 || relations != 0 || types != 0 || audits != 0 {
		t.Fatal("partial client/type state committed", roots, relations, types, audits, err)
	}
	if _, err := e.admin.Exec(ctx, `DROP TRIGGER fail_client ON mayi.outbox_events`); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- s.CreateClient(ctx, actor, actor.Scope, client) }()
	}
	wins, conflicts := 0, 0
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			wins++
		case errors.Is(err, administration.ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("client creation race", wins, conflicts)
	}
	got, err := s.Client(ctx, actor, actor.Scope, client.ID)
	if err != nil || len(got.AuthorizationDetailsTypes) != 1 || got.AuthorizationDetailsTypes[0] != client.AuthorizationDetailsTypes[0] {
		t.Fatal("client types not rehydrated", got.AuthorizationDetailsTypes, err)
	}
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.audit_events a JOIN mayi.outbox_events o USING(tenant_id,event_id) WHERE a.tenant_id='a' AND a.event_type='client_created' AND a.object_ref=$1`, client.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("client creation not atomically audited", audits, err)
	}
}

func TestP2ClientTypesDenyUnknownForeignAndUnassignedResourceDefinitions(t *testing.T) {
	e, _, request, _ := setupAuthorization(t)
	s, actor, _ := profileManagement(t, e, request.TenantIssuer)
	actor.Permissions = []string{"clients:write"}
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.resources VALUES('a','other','https://other.example','Other',300,false);
 INSERT INTO mayi.resource_object_profiles VALUES('a','other','https://other.example','https://other.example/types/file/v1','object-actions-v1','{"download":"Download file"}'),('b','api','https://api.example','https://api.example/types/foreign/v1','object-actions-v1','{"read":"Read"}')`); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"https://api.example/types/unknown/v1", "https://api.example/types/foreign/v1", "https://other.example/types/file/v1"} {
		input := objectClient("forbidden")
		input.AuthorizationDetailsTypes = []string{typ}
		if err := s.CreateClient(ctx, actor, actor.Scope, input); !errors.Is(err, administration.ErrInvalid) {
			t.Fatal("type outside client resource catalog accepted", typ, err)
		}
	}
	foreign := actor
	foreign.Scope = grants.Scope{TenantID: "b", Issuer: "https://auth.example/t/b"}
	if err := s.CreateClient(ctx, foreign, actor.Scope, objectClient("foreign")); !errors.Is(err, administration.ErrDenied) {
		t.Fatal("foreign actor created client type bindings", err)
	}
	for _, query := range []string{
		`INSERT INTO mayi.client_object_types VALUES('a','web','other','https://other.example/types/file/v1')`,
		`INSERT INTO mayi.client_object_types VALUES('a','web','api','https://other.example/types/file/v1')`,
		`INSERT INTO mayi.client_object_types VALUES('a','web','api','https://api.example/types/foreign/v1')`,
		`UPDATE mayi.client_object_types SET type_uri=type_uri WHERE tenant_id='a'`,
		`DELETE FROM mayi.client_object_types WHERE tenant_id='a'`,
	} {
		if _, err := e.admin.Exec(ctx, query); err == nil {
			t.Fatal("type binding constraints failed", query)
		}
	}
	tx, err := e.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('mayi.tenant_id','a',true)`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mayi.client_object_types WHERE tenant_id='b'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("client type RLS leaked", count, err)
	}
	_, err = tx.Exec(ctx, `UPDATE mayi.client_object_types SET type_uri=type_uri WHERE tenant_id='a'`)
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("runtime received client type UPDATE privilege", err)
	}
}

func TestP2AuthorizationProjectionSelectsOnlyClientAllowedResourceProfiles(t *testing.T) {
	e, consent, request, proof := setupAuthorization(t)
	s, actor, spec := profileManagement(t, e, request.TenantIssuer)
	actor.Permissions = []string{"resources:write", "clients:write"}
	ctx := context.Background()
	if err := s.RegisterObjectProfile(ctx, actor, actor.Scope, "api", spec); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.resources VALUES('a','other','https://other.example','Other',300,false);
 INSERT INTO mayi.resource_object_profiles VALUES('a','other','https://other.example','https://other.example/types/file/v1','object-actions-v1','{"download":"Download file"}')`); err != nil {
		t.Fatal(err)
	}
	client := objectClient("rar-client")
	client.Resources = []string{"api", "other"}
	client.AuthorizationDetailsTypes = []string{spec.Type, "https://other.example/types/file/v1"}
	if err := s.CreateClient(ctx, actor, actor.Scope, client); err != nil {
		t.Fatal(err)
	}
	request.ClientID = client.ID
	request.ObjectCeiling = registeredProfileCeiling(t, spec)
	err := e.store.RunAuthorization(ctx, actor.Scope, func(tx authorization.Transaction) error {
		current, err := tx.Registration(ctx, client.ID, request.ResourceURI)
		if err != nil {
			return err
		}
		if len(current.Client.AuthorizationDetailsTypes) != 2 || len(current.ObjectProfiles) != 1 || current.ObjectProfiles[0].Snapshot().Type != spec.Type || !request.MatchesObjectRegistration(current) {
			t.Fatal("projection mixed resource/type authority or enabled consent")
		}
		unallowed := current
		unallowed.Client.AuthorizationDetailsTypes = []string{"https://api.example/types/fixture/v1"}
		if request.MatchesObjectRegistration(unallowed) {
			t.Fatal("unallowed type accepted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Vocabulary registration does not bypass PAR, consent or object policy.
	if result, err := consent.Begin(ctx, request, proof.BrowserBindingHash); !errors.Is(err, authorization.ErrInvalid) || result.Handle != "" {
		t.Fatal("type allowlist prematurely enabled object authorization", err)
	}
}

func registeredProfileCeiling(t *testing.T, spec resources.ObjectProfileSpec) grants.ObjectCeiling {
	t.Helper()
	profile, err := resources.NewObjectProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	ceiling, err := profile.ValidateRequest(spec.Scope, spec.Resource, []grants.ObjectDetail{{Type: spec.Type, Identifier: "workflow:123", Actions: []string{"execute"}}})
	if err != nil {
		t.Fatal(err)
	}
	return ceiling
}

func TestP2ClientTypeMetadataHTTPRequiresExplicitRegisteredTypes(t *testing.T) {
	e := setupFoundation(t)
	h := e.server(t).Handler
	if w := api(t, h, "POST", "/admin/t/a/resources", e.tokens["a"], `{"id":"api","uri":"https://api.example","name":"API","scopes":[{"name":"read","description":"Read objects"}],"access_token_seconds":300,"require_binding":true}`); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api(t, h, "POST", "/admin/t/a/resources/api/object-profiles", e.tokens["a"], `{"resource":"https://api.example","type":"https://api.example/types/workflow/v1","semantics":"object-actions-v1","actions":[{"name":"read","description":"Read workflow"}]}`); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	body := `{"id":"rar-client","name":"Web","redirect_uris":["https://app.example/cb"],"resources":["api"],"access_token_seconds":300,"enabled":true,"authorization_details_types":["https://api.example/types/workflow/v1"]}`
	for _, replacement := range []string{"null", "[]", `["https://api.example/types/unknown/v1"]`, `["https://api.example/types/workflow/v1","https://api.example/types/workflow/v1"]`, `["http://api.example/types/workflow/v1"]`} {
		bad := strings.Replace(body, `["https://api.example/types/workflow/v1"]`, replacement, 1)
		if w := api(t, h, "POST", "/admin/t/a/clients", e.tokens["a"], bad); w.Code != 400 {
			t.Fatal("invalid type metadata accepted", replacement, w.Code, w.Body.String())
		}
	}
	missing := strings.Replace(body, `,"authorization_details_types":["https://api.example/types/workflow/v1"]`, "", 1)
	if w := api(t, h, "POST", "/admin/t/a/clients", e.tokens["a"], missing); w.Code != 400 {
		t.Fatal("missing types accepted", w.Code)
	}
	if w := api(t, h, "POST", "/admin/t/a/clients", e.tokens["b"], body); w.Code != 403 {
		t.Fatal("foreign client type registration accepted", w.Code)
	}
	if w := api(t, h, "POST", "/admin/t/a/clients", e.tokens["a"], body); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := api(t, h, "GET", "/admin/t/a/clients/rar-client", e.tokens["a"], "")
	var saved struct {
		Types []string `json:"authorization_details_types"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || len(saved.Types) != 1 || saved.Types[0] != "https://api.example/types/workflow/v1" {
		t.Fatal("client type metadata round trip", w.Code, w.Body.String())
	}
}
