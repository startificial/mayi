package app

import "testing"

func TestIssuerUsesStableTenantIdentity(t *testing.T) {
	a, err := NewIssuerScope("https://auth.example", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIssuerScope("https://auth.example", "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer != "https://auth.example/t/tenant-a" || a == b || a.Issuer == b.Issuer {
		t.Fatal("issuers collide")
	}
}
func TestIssuerRejectsAmbiguousOrUntrustedConfiguration(t *testing.T) {
	for _, origin := range []string{"http://auth.example", "https://auth.example/", "https://auth.example/base", "https://user:secret@auth.example", "https://auth.example?", "https://auth.example?tenant=b", "https://auth.example#fragment", "https://auth.example.", "https://AUTH.example", "https://auth.example:0", "https://auth.example:65536", "https://bad_host.example", "https://auth.example\\evil"} {
		t.Run(origin, func(t *testing.T) {
			if _, err := NewIssuerScope(origin, "tenant-a"); err == nil {
				t.Fatal("ambiguous issuer accepted")
			}
		})
	}
	for _, id := range []string{"", "../b", "a/b", "a%2fb", "a?x=b", "a b", "-a", "a-", "UPPER"} {
		if _, err := NewIssuerScope("https://auth.example", id); err == nil {
			t.Fatalf("invalid tenant ID accepted: %q", id)
		}
	}
	if _, err := NewIssuerScope("https://auth.example:8443", "a"); err != nil {
		t.Fatal(err)
	}
}
