package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestMPLNeedsExactUnmodifiedSourceAccess(t *testing.T) {
	root := t.TempDir()
	text := []byte("reviewed license evidence")
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), text, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(text)
	dep := dependency{Name: "github.com/HashiCorp/example", Version: "v1.2.3", Licenses: []string{"MPL-2.0"}, Source: "https://example.com/LICENSE", Review: "fixture", Files: []evidenceFile{{Path: "LICENSE", SHA256: hex.EncodeToString(digest[:])}}}
	allowed := map[string]bool{"MPL-2.0": true}
	if err := validateEvidence(dep, allowed, root); err == nil {
		t.Fatal("MPL accepted without source offer")
	}
	dep.SourceAccess = &sourceAccess{URL: moduleArchiveURL(dep.Name, dep.Version), ModificationStatus: "modified"}
	if err := validateEvidence(dep, allowed, root); err == nil {
		t.Fatal("upstream link accepted for modified source")
	}
	dep.SourceAccess.ModificationStatus = "unmodified"
	dep.SourceAccess.URL = "https://example.com/main.zip"
	if err := validateEvidence(dep, allowed, root); err == nil {
		t.Fatal("mutable source offer accepted")
	}
	dep.SourceAccess.URL = moduleArchiveURL(dep.Name, dep.Version)
	if err := validateEvidence(dep, allowed, root); err != nil {
		t.Fatal(err)
	}
	if dep.SourceAccess.URL != "https://proxy.golang.org/github.com/!hashi!corp/example/@v/v1.2.3.zip" {
		t.Fatal("incorrect module escaping")
	}
}

func TestMPLDistributionNoticeCannotOmitSourceOrLicense(t *testing.T) {
	root := t.TempDir()
	license, err := os.ReadFile(filepath.Join("..", "..", "tools", "license-evidence", "MPL-2.0.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "tools/license-evidence"), 0700); err != nil {
		t.Fatal(err)
	}
	licensePath := filepath.Join(root, "tools/license-evidence/MPL-2.0.txt")
	if err := os.WriteFile(licensePath, license, 0600); err != nil {
		t.Fatal(err)
	}
	dep := dependency{Name: "github.com/example/dependency", Version: "v1.2.3", Licenses: []string{"MPL-2.0"}, SourceAccess: &sourceAccess{URL: "https://proxy.golang.org/github.com/example/dependency/@v/v1.2.3.zip", ModificationStatus: "unmodified"}}
	noticePath := filepath.Join(root, "THIRD_PARTY_NOTICES.md")
	if err := os.WriteFile(noticePath, []byte(dep.Name+"@"+dep.Version), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateMPLNotices(root, []dependency{dep}); err == nil {
		t.Fatal("notice omitted source archive")
	}
	if err := os.WriteFile(noticePath, []byte(dep.Name+"@"+dep.Version+" "+dep.SourceAccess.URL), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateMPLNotices(root, []dependency{dep}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(licensePath, []byte("truncated license"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateMPLNotices(root, []dependency{dep}); err == nil {
		t.Fatal("truncated license accepted")
	}
}

func TestModuleSourceArchiveEscapesVersionCase(t *testing.T) {
	if got := moduleArchiveURL("example.com/Module", "v1.0.0-RC1"); got != "https://proxy.golang.org/example.com/!module/@v/v1.0.0-!r!c1.zip" {
		t.Fatalf("incorrect source archive: %s", got)
	}
}
