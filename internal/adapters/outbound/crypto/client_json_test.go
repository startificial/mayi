package crypto

import "testing"

func TestClientJSONRejectsDuplicateEscapedAndCaseVariantMembers(t *testing.T) {
	for _, raw := range []string{`{"iss":"one","iss":"two"}`, `{"iss":"one","\u0069ss":"two"}`, `{"ISS":"one"}`, `{"iss":"one"} trailing`, `{"iss":null,"jku":"https://attacker.example"}`} {
		if _, ok := clientObject([]byte(raw), "iss"); ok {
			t.Fatal("ambiguous client JSON accepted", raw)
		}
	}
	if _, ok := clientObject([]byte(`{"iss":"one"}`), "iss"); !ok {
		t.Fatal("valid client JSON rejected")
	}
	for _, raw := range []string{`{"keys":[],"keys":[]}`, `{"Keys":[]}`, `{"keys":[{"kty":"RSA","n":"one","n":"two"}]}`, `{"keys":[{"kty":"RSA","x5u":"https://attacker.example/key"}]}`} {
		if strictClientKeys([]byte(raw)) {
			t.Fatal("ambiguous registered JWKS accepted", raw)
		}
	}
}
