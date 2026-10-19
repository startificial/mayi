package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/administration"
)

type profileKeys struct{ t *testing.T }

func (k profileKeys) PublicKey(context.Context, grants.Scope, int) (identity.PublicKey, error) {
	k.t.Fatal("profile operation reached signing keys")
	return identity.PublicKey{}, administration.ErrUnavailable
}

func profileManagement(t *testing.T, e *foundation, scope grants.Scope) (*administration.Service, administration.Actor, resources.ObjectProfileSpec) {
	t.Helper()
	s, err := administration.New(e.store, profileKeys{t}, clock{})
	if err != nil {
		t.Fatal(err)
	}
	return s, administration.Actor{ID: "admin", Scope: scope, Permissions: []string{"resources:read", "resources:write"}}, resources.ObjectProfileSpec{Scope: scope, Resource: "https://api.example", Type: "https://api.example/types/workflow/v1", Semantics: resources.ObjectActionsV1, Actions: []resources.ObjectAction{{Name: "execute", Description: "Execute this workflow"}, {Name: "read", Description: "Read this workflow"}}}
}

func TestP2RegisteredObjectProfilesRemainTenantAndAudienceBound(t *testing.T) {
	e, _, request, _ := setupAuthorization(t)
	s, actor, spec := profileManagement(t, e, request.TenantIssuer)
	ctx := context.Background()
	if err := s.RegisterObjectProfile(ctx, actor, actor.Scope, "api", spec); err != nil {
		t.Fatal(err)
	}
	got, err := s.ObjectProfile(ctx, actor, actor.Scope, "api", spec.Type)
	if err != nil {
		t.Fatal(err)
	}
	ceiling, err := got.ValidateRequest(actor.Scope, spec.Resource, []grants.ObjectDetail{{Type: spec.Type, Identifier: "workflow:123", Actions: []string{"execute"}}})
	if err != nil || !ceiling.Permits(actor.Scope, spec.Resource, spec.Type, "workflow:123", "execute") || ceiling.Permits(actor.Scope, spec.Resource, spec.Type, "workflow:124", "execute") {
		t.Fatal("rehydrated profile changed tuple semantics", err)
	}
	if _, err := got.ValidateRequest(actor.Scope, spec.Resource, []grants.ObjectDetail{{Type: spec.Type, Identifier: "workflow:123", Actions: []string{"delete"}}}); err == nil {
		t.Fatal("unregistered action accepted")
	}
	foreign := grants.Scope{TenantID: "b", Issuer: "https://auth.example/t/b"}
	if _, err := s.ObjectProfile(ctx, actor, foreign, "api", spec.Type); !errors.Is(err, administration.ErrDenied) {
		t.Fatal("foreign actor read profile", err)
	}
	other := actor
	other.Scope = foreign
	if _, err := s.ObjectProfile(ctx, other, foreign, "api", spec.Type); !errors.Is(err, administration.ErrNotFound) {
		t.Fatal("profile leaked into another tenant", err)
	}
	otherSpec := spec
	otherSpec.Scope = foreign
	otherSpec.Actions = []resources.ObjectAction{{Name: "download", Description: "Download object"}}
	if err := s.RegisterObjectProfile(ctx, other, foreign, "api", otherSpec); err != nil {
		t.Fatal("independent tenant registration failed", err)
	}
	got, err = s.ObjectProfile(ctx, actor, actor.Scope, "api", spec.Type)
	if err != nil || len(got.Snapshot().Actions) != 2 {
		t.Fatal("foreign definition replaced local semantics", err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.resources VALUES('a','other','https://other.example','Other',300,false)`); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterObjectProfile(ctx, actor, actor.Scope, "other", spec); !errors.Is(err, administration.ErrInvalid) {
		t.Fatal("wrong resource audience accepted", err)
	}
	reassigned := spec
	reassigned.Resource = "https://other.example"
	if err := s.RegisterObjectProfile(ctx, actor, actor.Scope, "other", reassigned); !errors.Is(err, administration.ErrConflict) {
		t.Fatal("registered type moved to another resource", err)
	}
	if _, err := s.ObjectProfile(ctx, actor, actor.Scope, "other", spec.Type); !errors.Is(err, administration.ErrNotFound) {
		t.Fatal("profile resolved by type without resource binding", err)
	}
	tx, err := e.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('mayi.tenant_id','a',true)`); err != nil {
		t.Fatal(err)
	}
	var leaked int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mayi.resource_object_profiles WHERE tenant_id='b'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("profile RLS leaked", leaked, err)
	}
}

func TestP2ProfileRegistrationRollsBackAndHasOneConcurrentWinner(t *testing.T) {
	e, _, request, _ := setupAuthorization(t)
	s, actor, spec := profileManagement(t, e, request.TenantIssuer)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `CREATE FUNCTION mayi.fail_profile_outbox() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test outbox failure'; END$$; CREATE TRIGGER fail_profile BEFORE INSERT ON mayi.outbox_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_profile_outbox()`); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterObjectProfile(ctx, actor, actor.Scope, "api", spec); !errors.Is(err, administration.ErrUnavailable) {
		t.Fatal("uncommitted registration acknowledged", err)
	}
	var profiles, audits, events int
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mayi.resource_object_profiles WHERE type_uri=$1),(SELECT count(*) FROM mayi.audit_events),(SELECT count(*) FROM mayi.outbox_events)`, spec.Type).Scan(&profiles, &audits, &events); err != nil || profiles != 0 || audits != 0 || events != 0 {
		t.Fatal("partial registration committed", profiles, audits, events, err)
	}
	if _, err := e.admin.Exec(ctx, `DROP TRIGGER fail_profile ON mayi.outbox_events`); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- s.RegisterObjectProfile(ctx, actor, actor.Scope, "api", spec) }()
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
		t.Fatal("registration race", wins, conflicts)
	}
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM mayi.audit_events a JOIN mayi.outbox_events o USING(tenant_id,event_id) WHERE a.tenant_id='a' AND a.event_type='object_profile_registered'`).Scan(&events); err != nil || events != 1 {
		t.Fatal("registration audit/outbox not atomic", events, err)
	}
}

func TestP2RegisteredProfileSemanticsAndAudienceCannotBeRewritten(t *testing.T) {
	e, _, request, _ := setupAuthorization(t)
	s, actor, spec := profileManagement(t, e, request.TenantIssuer)
	ctx := context.Background()
	if err := s.RegisterObjectProfile(ctx, actor, actor.Scope, "api", spec); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE mayi.resource_object_profiles SET actions='{"delete":"Delete all"}' WHERE tenant_id='a'`,
		`UPDATE mayi.resource_object_profiles SET type_uri='https://api.example/types/workflow/v2' WHERE tenant_id='a'`,
		`DELETE FROM mayi.resource_object_profiles WHERE tenant_id='a'`,
		`UPDATE mayi.resources SET uri='https://changed.example' WHERE tenant_id='a' AND resource_id='api'`,
	} {
		if _, err := e.admin.Exec(ctx, query); err == nil {
			t.Fatal("immutable profile binding changed", query)
		}
	}
	// Malformed owner-supplied records must fail rehydration, rather than being
	// interpreted as a broad/default profile by a trusted in-process caller.
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.resource_object_profiles VALUES('a','api','https://api.example','https://api.example/types/bad/v1','object-actions-v1','{"read":null}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObjectProfile(ctx, actor, actor.Scope, "api", "https://api.example/types/bad/v1"); !errors.Is(err, administration.ErrUnavailable) {
		t.Fatal("malformed registered profile accepted", err)
	}
}

func TestP2ProfileManagementHTTPValidatesAndDoesNotAdvertiseRAR(t *testing.T) {
	e := setupFoundation(t)
	h := e.server(t).Handler
	if w := api(t, h, "POST", "/admin/t/a/resources", e.tokens["a"], `{"id":"api","uri":"https://api.example","name":"API","scopes":[{"name":"read","description":"Read objects"}],"access_token_seconds":300,"require_binding":true}`); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	path := "/admin/t/a/resources/api/object-profiles"
	body := `{"resource":"https://api.example","type":"https://api.example/types/workflow/v1","semantics":"object-actions-v1","actions":[{"name":"execute","description":"Execute workflow"}]}`
	for _, token := range []string{"", e.tokens["b"]} {
		w := api(t, h, "POST", path, token, body)
		if w.Code != 401 && w.Code != 403 {
			t.Fatal("unauthorized profile registration", w.Code)
		}
	}
	if w := api(t, h, "POST", path, e.tokens["a"], body); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, invalid := range []string{
		strings.Replace(body, "object-actions-v1", "allow-all", 1),
		strings.Replace(body, `"resource":"https://api.example"`, `"resource":"https://foreign.example"`, 1),
		strings.Replace(body, `"type":"https://api.example/types/workflow/v1"`, `"type":"http://api.example/types/workflow/v1"`, 1),
		strings.Replace(body, `"name":"execute"`, `"name":"*"`, 1),
		strings.TrimSuffix(body, "}") + `,"tenant_id":"b"}`,
	} {
		if w := api(t, h, "POST", path, e.tokens["a"], invalid); w.Code != 400 {
			t.Fatal("invalid profile registration accepted", w.Code, w.Body.String())
		}
	}
	if w := api(t, h, "PUT", path, e.tokens["a"], body); w.Code != 405 {
		t.Fatal("profile mutation route exists", w.Code)
	}
	query := "?type=" + url.QueryEscape("https://api.example/types/workflow/v1")
	w := api(t, h, "GET", path+query, e.tokens["a"], "")
	var result struct {
		Type, Semantics string
		Actions         []struct{ Name, Description string }
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Type != "https://api.example/types/workflow/v1" || len(result.Actions) != 1 || result.Actions[0].Name != "execute" {
		t.Fatal("profile management round trip", w.Code, w.Body.String())
	}
	if w := api(t, h, "POST", path, e.tokens["a"], body); w.Code != 409 {
		t.Fatal("profile replacement accepted", w.Code)
	}
	for _, query := range []string{"", "?type=bad", query + "&type=other", query + "&unknown=value", "?type=%zz"} {
		if w := api(t, h, "GET", path+query, e.tokens["a"], ""); w.Code != 400 {
			t.Fatal("invalid profile lookup accepted", query, w.Code)
		}
	}
	if w := api(t, h, "GET", path+query, e.tokens["b"], ""); w.Code != 403 {
		t.Fatal("foreign profile read", w.Code)
	}
	w = api(t, h, "GET", "/.well-known/oauth-authorization-server/t/a", "", "")
	var metadata map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &metadata) != nil || metadata["authorization_details_types_supported"] != nil || metadata["pushed_authorization_request_endpoint"] != nil {
		t.Fatal("registration prematurely advertised live capability", w.Code, w.Body.String())
	}
}
