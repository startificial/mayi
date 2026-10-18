package app

import (
	"testing"
)

func TestUpstreamProviderConfigurationBoundary(t *testing.T) {
	c := Config{PublicOrigin: "https://auth.example"}
	valid := IdentityProviderConfig{ID: "provider", Issuer: "https://idp.example", ClientID: "mayi", ClientSecretEnv: "MAYI_IDP_SECRET", AuthorizationEndpoint: "https://idp.example/authorize", TokenEndpoint: "https://idp.example/token", JWKSURI: "https://idp.example/jwks", SigningAlgorithm: "RS256"}
	if err := validateIdentityProvider(c, &valid); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"HTTP", "query", "fragment", "credentials", "missing secret reference", "algorithm", "empty client"} {
		t.Run(mode, func(t *testing.T) {
			p := valid
			switch mode {
			case "HTTP":
				p.Issuer = "http://idp.example"
			case "query":
				p.TokenEndpoint += "?secret=bad"
			case "fragment":
				p.JWKSURI += "#key"
			case "credentials":
				p.TokenEndpoint = "https://user:secret@idp.example/token"
			case "missing secret reference":
				p.ClientSecretEnv = ""
			case "algorithm":
				p.SigningAlgorithm = "HS256"
			case "empty client":
				p.ClientID = ""
			}
			if validateIdentityProvider(c, &p) == nil {
				t.Fatal("unsafe provider config accepted")
			}
		})
	}
}
