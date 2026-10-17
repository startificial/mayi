package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestServiceAdmissionRejectsUnknownComponentAndChangedNotice(t *testing.T) {
	root := t.TempDir()
	license := "reviewed license fixture"
	hash := sha256.Sum256([]byte(license))
	evidence := []evidenceFile{{Path: "license.txt", SHA256: hex.EncodeToString(hash[:])}}
	writeFixture(t, root, "license.txt", license)
	save := func(path string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, root, path, string(b))
	}
	save("tools/license-policy.json", licensePolicy{Version: 1, Allowed: []string{"MIT"}})
	entries := serviceInventory{Version: 1, Artifacts: []serviceArtifact{
		{Name: "postgresql", Version: "1", Licenses: []string{"MIT"}, Source: "https://example.com/pg.tar.gz", SHA256: hex.EncodeToString(hash[:]), Review: "fixture", Files: evidence},
		{Name: "openbao", Version: "1", Licenses: []string{"MIT"}, Source: "https://example.com/bao.tar.gz", SHA256: hex.EncodeToString(hash[:]), Review: "fixture", Files: evidence},
	}}
	save("tools/services.json", entries)
	components := []map[string]any{{"name": "module", "version": "v1", "licenses": []string{"MIT"}, "source": "https://example.com/source", "review": "fixture"}}
	save("docs/p0/openbao-components.json", components)
	if err := checkServices(root); err != nil {
		t.Fatal(err)
	}
	components[0]["licenses"] = []string{"GPL-3.0-only"}
	save("docs/p0/openbao-components.json", components)
	if err := checkServices(root); err == nil {
		t.Fatal("disallowed nested license hidden by allowed service label")
	}
	components[0]["licenses"] = []string{"MIT"}
	save("docs/p0/openbao-components.json", components)
	writeFixture(t, root, "license.txt", "tampered")
	if err := checkServices(root); err == nil {
		t.Fatal("modified service notice accepted")
	}
	entries.Artifacts[0].Files[0].Path = filepath.Join("..", "outside")
	save("tools/services.json", entries)
	if err := checkServices(root); err == nil {
		t.Fatal("escaping evidence path accepted")
	}
}
