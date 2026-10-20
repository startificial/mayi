package tokens

import "testing"

func TestProofTargetsKeepAuthorityAndEscapedPaths(t *testing.T) {
	for _, pair := range [][2]string{{"https://API.example:443", "https://api.example/"}, {"https://api.example:8443/a%2Fb?q=1", "https://api.example:8443/a%2Fb"}, {"https://[::1]:443/a", "https://[::1]/a"}} {
		got, ok := ProofTarget(pair[0], false)
		if !ok || got != pair[1] {
			t.Fatal("incorrect target normalization", pair, got)
		}
	}
	for _, raw := range []string{"http://api.example/a", "https://user@api.example/a", "https://api.example/a#fragment", "https://api.example/a/../b", "https://api.example/a/%2e%2e/b", "https://api.example/a\\b", "https://api.example/a?x=%zz"} {
		if _, ok := ProofTarget(raw, false); ok {
			t.Fatal("unsafe target", raw)
		}
	}
	for _, raw := range []string{"https://api.example/a?q=1", "https://api.example/a?"} {
		if _, ok := ProofTarget(raw, true); ok {
			t.Fatal("proof htu included query", raw)
		}
	}
	a, _ := ProofTarget("https://api.example/a%2Fb", true)
	b, _ := ProofTarget("https://api.example/a/b", true)
	if a == b {
		t.Fatal("escaped path authority changed")
	}
}
