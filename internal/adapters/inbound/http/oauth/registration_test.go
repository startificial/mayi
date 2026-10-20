package oauth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistrationWireRejectsAmbiguousOrUnsupportedAuthority(t *testing.T) {
	valid := `{"client_name":"Agent","redirect_uris":["https://agent.example/cb"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"mayi_resource_ids":["api"],"authorization_details_types":["https://api.example/types/item"],"unknown_extension":"ignored"}`
	for _, bad := range []string{
		strings.Replace(valid, `"client_name":"Agent"`, `"client_name":"Agent","client_name":"Other"`, 1),
		strings.Replace(valid, `"client_name":"Agent"`, `"Client_Name":"Agent"`, 1),
		strings.Replace(valid, `"client_name":"Agent"`, `"client_name":"Agent","Client_Name":"Other"`, 1),
		strings.Replace(valid, `"none"`, `"client_secret_basic"`, 1),
		strings.Replace(valid, `"refresh_token"`, `"client_credentials"`, 1),
		strings.Replace(valid, `"ignored"`, `null`, 1),
		strings.Replace(valid, `"unknown_extension":"ignored"`, `"client_id":"chosen"`, 1),
		strings.Replace(valid, `"unknown_extension":"ignored"`, `"software_statement":"untrusted"`, 1),
		valid + `{}`, strings.Repeat(" ", 32769), `[]`,
	} {
		r := httptest.NewRequest("POST", "https://auth.example/t/a/register", strings.NewReader(bad))
		r.Header.Set("Content-Type", "application/json")
		if _, ok := registrationInput(httptest.NewRecorder(), r); ok {
			t.Fatal("unsafe registration body admitted")
		}
	}
	r := httptest.NewRequest("POST", "https://auth.example/t/a/register", strings.NewReader(valid))
	r.Header.Set("Content-Type", "application/json")
	input, ok := registrationInput(httptest.NewRecorder(), r)
	if !ok || input.ClientID != "" || !input.RequireBinding || input.ApplicationType != "web" {
		t.Fatal("public profile mapping failed")
	}
}
