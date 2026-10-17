package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestSpecificationSourcesMustBePinned(t *testing.T) {
	cases := map[string]bool{
		"https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt":  true,
		"https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1.txt":     false,
		"https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-xx.txt":  false,
		"https://www.rfc-editor.org/rfc/rfc9449.txt":                    true,
		"https://www.rfc-editor.org/rfc/latest.txt":                     false,
		"https://openid.net/specs/openid-connect-core-1_0-errata2.html": true,
		"https://openid.net/specs/openid-connect-core-1_0.html":         false,
		"https://raw.githubusercontent.com/modelcontextprotocol/ext-auth/fb374c7db2b34f18ca9183882e0beecdf661892b/specification/stable/enterprise-managed-authorization.mdx": true,
		"https://raw.githubusercontent.com/modelcontextprotocol/ext-auth/main/specification/stable/enterprise-managed-authorization.mdx":                                     false,
		"https://example.com/rfc/rfc9449.txt": false,
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := pinnedSpecURL(u); got != want {
				t.Fatalf("pin validation=%v, want %v", got, want)
			}
		})
	}
}

func TestSpecificationManifestRejectsIncompleteAndMutablePins(t *testing.T) {
	var baseline specificationManifest
	if err := readJSON(filepath.Join("..", "..", "specs", "manifest.yaml"), &baseline); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*specificationManifest){
		"missing required draft": func(m *specificationManifest) { m.Documents = m.Documents[1:] },
		"duplicate":              func(m *specificationManifest) { m.Documents = append(m.Documents, m.Documents[0]) },
		"empty digest":           func(m *specificationManifest) { m.Documents[0].SHA256 = "" },
		"bad date":               func(m *specificationManifest) { m.Documents[0].RetrievedOn = "yesterday" },
		"invalid phase":          func(m *specificationManifest) { m.Documents[0].TargetPhase = "P9" },
		"mutable source": func(m *specificationManifest) {
			m.Documents[0].URL = "https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1.txt"
		},
		"insecure source": func(m *specificationManifest) {
			m.Documents[0].URL = "http://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m := baseline
			m.Documents = append([]specification(nil), baseline.Documents...)
			change(&m)
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "specs"), 0700); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, root, "specs/manifest.yaml", string(data))
			if err := checkSpecifications(root); err == nil {
				t.Fatal("invalid pin accepted")
			}
		})
	}
}
