package clients

import "testing"

func TestNativeCallbackPoliciesPreserveExactDestination(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1/cb", "http://127.0.0.1:51004/cb?provider=mayi", "http://[::1]:61023/cb", "com.example.app:/oauth/cb?provider=mayi", "com.example.123app:/cb", "https://app.example/native/cb"} {
		if !ValidApplicationRedirect("native", raw) {
			t.Fatal("valid native callback rejected", raw)
		}
	}
	for _, raw := range []string{"http://localhost:3000/cb", "http://127.0.0.2/cb", "http://127.1/cb", "http://2130706433/cb", "http://[::ffff:127.0.0.1]/cb", "http://127.0.0.1.evil/cb", "http://user@127.0.0.1/cb", "http://127.0.0.1:0/cb", "http://127.0.0.1:03000/cb", "http://127.0.0.1:65536/cb", "http://127.0.0.1:/cb", "http://127.0.0.1/cb#", "com.example.app://host/cb", "com.example.app:opaque", "com.example.app:///cb", "app:/cb", "javascript:/cb", "com.example.app:/cb?%73tate=fixed", "com.example.app:/cb?x=%zz", "com.example.app:/cb\r\nX:injected", "com.example.app:/cb?x=\""} {
		if ValidApplicationRedirect("native", raw) {
			t.Fatal("unsafe native callback accepted", raw)
		}
	}
	for _, pair := range [][2]string{{"http://127.0.0.1/cb?provider=mayi", "http://127.0.0.1:54321/cb?provider=mayi"}, {"http://[::1]:3000/cb", "http://[::1]:61023/cb"}} {
		if !RedirectMatches("native", pair[0], pair[1]) {
			t.Fatal("loopback port exception rejected", pair)
		}
	}
	for _, pair := range [][2]string{{"http://127.0.0.1/cb", "http://[::1]:54321/cb"}, {"http://127.0.0.1/cb", "http://127.0.0.1:54321/other"}, {"http://127.0.0.1/cb?x=%2f", "http://127.0.0.1:54321/cb?x=%2F"}, {"http://127.0.0.1/cb", "http://127.0.0.1:54321/cb?"}, {"com.example.app:/cb", "com.example.other:/cb"}, {"https://app.example/cb", "https://app.example:8443/cb"}, {"http://127.0.0.1/cb%2f", "http://127.0.0.1/cb/"}} {
		if RedirectMatches("native", pair[0], pair[1]) {
			t.Fatal("native exception changed destination", pair)
		}
	}
}

func TestNativeApplicationRequiresPublicRegistration(t *testing.T) {
	c := Client{ID: "native-app", Name: "Desktop", ApplicationType: "native", RedirectURIs: []string{"http://127.0.0.1/cb", "com.example.app:/cb"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/fixture/v1"}, AccessTokenSeconds: 300, Enabled: true}
	if !c.Valid() || !c.AllowsRedirect("http://127.0.0.1:54321/cb") || c.AllowsRedirect("http://127.0.0.1:54321/other") {
		t.Fatal("native registration policy")
	}
	for _, method := range []string{"client_secret_basic", "private_key_jwt"} {
		c.AuthMethod = method
		if c.Valid() {
			t.Fatal("native app became confidential", method)
		}
	}
	c.AuthMethod = "none"
	c.ApplicationType = "web"
	if c.Valid() || c.AllowsRedirect("http://127.0.0.1:54321/cb") {
		t.Fatal("web client inherited native exceptions")
	}
	c.ApplicationType = "other"
	if c.Valid() {
		t.Fatal("unknown application type accepted")
	}
}
