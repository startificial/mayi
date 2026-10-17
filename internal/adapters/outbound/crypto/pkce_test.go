package crypto

import (
	"strings"
	"testing"
)

func TestRFC7636S256Vector(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	pkce := New()
	if err := pkce.VerifyS256(challenge, verifier); err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		"wrong verifier":    {challenge, strings.Repeat("a", 43)},
		"plain":             {verifier, verifier},
		"short":             {challenge, "short"},
		"long":              {challenge, strings.Repeat("a", 129)},
		"invalid character": {challenge, strings.Repeat("a", 42) + " "},
		"padded challenge":  {challenge + "=", verifier},
		"empty":             {},
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			if err := pkce.VerifyS256(values[0], values[1]); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}
