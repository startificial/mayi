package clients

import "testing"

func TestWebRedirectPreservesFixedQueries(t *testing.T) {
	for _, uri := range []string{"https://app.example/callback?provider=mayi", "https://app.example:8443/cb?a=1&a=2&next=%2Fhome", "https://app.example/callback?", "https://app.example/cb%20here?x=%20", "https://app.example/cb?x=%5B%22value%22%5D"} {
		c := Client{ID: "web", Name: "Web", RedirectURIs: []string{uri}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}, AccessTokenSeconds: 300}
		if !c.Valid() || c.RedirectURIs[0] != uri {
			t.Fatalf("valid redirect rejected or changed: %q", uri)
		}
	}
}
func TestWebRedirectRejectsUnsafeOrMalformedDestinations(t *testing.T) {
	for _, uri := range []string{"http://app.example/cb", "https://user:secret@app.example/cb", "https://app.example/cb#fragment", "https://app.example/cb#", "https://app.example/cb?x=%zz", "https://app.example/%zz", "https://app.example/cb?x=bad value", "https://app.example\\evil/cb", "https://APP.example/cb", "https://app.example:0443/cb", "https://app.example:/cb", "https://app.example:65536/cb", "https://app.example./cb", "https://[::1]/cb", "https://app.example/cb\n"} {
		if ValidRedirectURI(uri) {
			t.Fatalf("unsafe redirect accepted: %q", uri)
		}
	}
	for _, character := range []string{"\"", "<", ">", "[", "]", "{", "}", "|", "^", "`"} {
		if ValidRedirectURI("https://app.example/cb?x=" + character) {
			t.Fatalf("unescaped query syntax accepted: %q", character)
		}
	}
	c := Client{ID: "web", Name: "Web", RedirectURIs: []string{"https://app.example/cb?x=1", "https://app.example/cb?x=1"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}, AccessTokenSeconds: 300}
	if c.Valid() {
		t.Fatal("duplicate redirects accepted")
	}
}

func TestAuthorizationRedirectRejectsReservedResponseQuery(t *testing.T) {
	for _, raw := range []string{"https://app.example/cb?code=old", "https://app.example/cb?state=fixed", "https://app.example/cb?%69ss=evil", "https://app.example/cb?error=bad"} {
		if ValidAuthorizationRedirect(raw) {
			t.Fatal("ambiguous authorization redirect", raw)
		}
	}
	if !ValidAuthorizationRedirect("https://app.example/cb?provider=mayi") {
		t.Fatal("fixed non-protocol query refused")
	}
}
