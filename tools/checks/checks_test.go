package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportBoundaries(t *testing.T) {
	cases := []struct {
		name, source, imported string
		test, allowed          bool
	}{
		{"service domain", "internal/services/tokens/service.go", modulePath + "/internal/domain/grants", false, true},
		{"service driver", "internal/services/tokens/service.go", "github.com/jackc/pgx/v5", false, false},
		{"service database", "internal/services/tokens/service.go", "database/sql", false, false},
		{"service HTTP", "internal/services/tokens/service.go", "net/http", false, false},
		{"domain service", "internal/domain/grants/grant.go", modulePath + "/internal/services/tokens", false, false},
		{"domain environment", "internal/domain/grants/grant.go", "os", false, false},
		{"handler service", "internal/adapters/inbound/http/oauth/token.go", modulePath + "/internal/services/tokens", false, true},
		{"handler database", "internal/adapters/inbound/http/oauth/token.go", "database/sql", false, false},
		{"handler driver", "internal/adapters/inbound/http/oauth/token.go", "github.com/jackc/pgx/v5/pgxpool", false, false},
		{"handler unknown driver", "internal/adapters/inbound/http/oauth/token.go", "example.test/database", false, false},
		{"handler protocol adapter", "internal/adapters/inbound/http/oauth/token.go", "github.com/ory/fosite", false, true},
		{"handler outbound", "internal/adapters/inbound/http/oauth/token.go", modulePath + "/internal/adapters/outbound/postgres", false, false},
		{"view service", "internal/adapters/inbound/web/component.go", modulePath + "/internal/services/grants", false, false},
		{"view rendering", "internal/adapters/inbound/web/component.go", "html/template", false, true},
		{"adapter port", "internal/adapters/outbound/postgres/grants.go", modulePath + "/internal/services/grants", false, true},
		{"adapter handler", "internal/adapters/outbound/postgres/grants.go", modulePath + "/internal/adapters/inbound/http/admin", false, false},
		{"composition", "internal/app/server.go", modulePath + "/internal/adapters/outbound/postgres", false, true},
		{"command composition", "cmd/mayi/main.go", modulePath + "/internal/app", false, true},
		{"command persistence", "cmd/mayi/main.go", modulePath + "/internal/adapters/outbound/postgres", false, false},
		{"sdk service", "pkg/resource/middleware.go", modulePath + "/internal/services/resource", false, true},
		{"sdk database", "pkg/resource/middleware.go", modulePath + "/internal/adapters/outbound/postgres", false, false},
		{"sdk SQL", "pkg/resource/middleware.go", "database/sql", false, false},
		{"sdk unrelated service", "pkg/resource/middleware.go", modulePath + "/internal/services/administration", false, false},
		{"domain test stdlib", "internal/domain/grants/grant_test.go", "os", true, true},
		{"domain test adapter bypass", "internal/domain/grants/grant_test.go", modulePath + "/internal/adapters/outbound/postgres", true, false},
		{"tool dependency", "tools/checks/main.go", "gopkg.in/yaml.v3", false, false},
		{"prefix bypass", "internal/services/tokens/service.go", modulePath + "/internal/domainfake/grants", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := importAllowed(tc.source, tc.imported, tc.test); got != tc.allowed {
				t.Fatalf("allowed = %v, want %v", got, tc.allowed)
			}
		})
	}
}

func writeFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestArchitectureReadsBuildTaggedFiles(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "internal/services/tokens/hidden.go", "//go:build never_enabled\n\npackage tokens\nimport _ \"database/sql\"\n")
	if err := checkArchitecture(root); err == nil || !strings.Contains(err.Error(), "forbidden import") {
		t.Fatalf("expected tagged forbidden import failure, got %v", err)
	}
}

func TestArchitectureRejectsUnclassifiedSource(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "internal/helpers/security.go", "package helpers\n")
	if err := checkArchitecture(root); err == nil {
		t.Fatal("unclassified source accepted")
	}
}

func sampleEvidence(t *testing.T) (string, dependency, map[string]bool) {
	t.Helper()
	root := t.TempDir()
	content := "synthetic license evidence used only in a unit test\n"
	writeFixture(t, root, "LICENSE", content)
	digest := sha256.Sum256([]byte(content))
	return root, dependency{
		Name: "example.test/dependency", Version: "v1.2.3", Licenses: []string{"MIT"},
		Source: "https://example.test/dependency/v1.2.3/LICENSE", Review: "synthetic fixture",
		Files: []evidenceFile{{Path: "LICENSE", SHA256: hex.EncodeToString(digest[:])}},
	}, map[string]bool{"MIT": true, "Apache-2.0": true}
}

func TestLicenseEvidence(t *testing.T) {
	for _, mode := range []string{"valid", "disallowed", "unknown", "changed", "missing", "traversal", "bundled-disallowed"} {
		t.Run(mode, func(t *testing.T) {
			root, dep, allowed := sampleEvidence(t)
			switch mode {
			case "disallowed":
				dep.Licenses = []string{"GPL-3.0-only"}
			case "unknown":
				dep.Licenses = []string{"UNKNOWN"}
			case "changed":
				writeFixture(t, root, "LICENSE", "changed license")
			case "missing":
				dep.Files = nil
			case "traversal":
				dep.Files[0].Path = "../LICENSE"
			case "bundled-disallowed":
				dep.Licenses = []string{"MIT", "GPL-3.0-only"}
			}
			err := validateEvidence(dep, allowed, root)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestEvidenceRejectsSymlinkEscape(t *testing.T) {
	root, dep, allowed := sampleEvidence(t)
	outside := t.TempDir()
	writeFixture(t, outside, "LICENSE", "outside")
	if err := os.Remove(filepath.Join(root, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "LICENSE"), filepath.Join(root, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	if err := validateEvidence(dep, allowed, root); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("expected escape rejection, got %v", err)
	}
}

func TestModuleGraphAdmission(t *testing.T) {
	for _, mode := range []string{"valid", "transitive-missing", "upgraded", "replace", "stale", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			root, dep, allowed := sampleEvidence(t)
			mods := []goModule{{Path: modulePath, Main: true}, {Path: dep.Name, Version: dep.Version, Dir: root}}
			approved := []dependency{dep}
			switch mode {
			case "transitive-missing":
				mods = append(mods, goModule{Path: "example.test/transitive", Version: "v2.0.0", Dir: root})
			case "upgraded":
				mods[1].Version = "v1.2.4"
			case "replace":
				mods[1].Replace = &goModule{Path: "../fork"}
			case "stale":
				mods = mods[:1]
			case "duplicate":
				approved = append(approved, dep)
			}
			err := validateModules(mods, approved, allowed)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestActionPins(t *testing.T) {
	pin := strings.Repeat("a", 40)
	dep := dependency{Name: "example/action", Version: pin}
	for _, tc := range []struct {
		name, workflow string
		pass           bool
	}{
		{"pinned", "    - uses: example/action@" + pin + " # v1\n", true},
		{"mutable", "    - uses: example/action@v1\n", false},
		{"unknown", "    - uses: other/action@" + pin + "\n", false},
		{"expression", "    - uses: ${{ inputs.action }}\n", false},
		{"flow-yaml", "    - { uses: example/action@" + pin + " }\n", false},
		{"spaced key", "    - uses : other/action@" + pin + "\n", false},
		{"quoted key", "    - 'uses': other/action@" + pin + "\n", false},
		{"stale", "jobs: {}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateActions([]string{tc.workflow}, []dependency{dep})
			if (err == nil) != tc.pass {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestForbiddenPackageBoundary(t *testing.T) {
	prefixes := []string{"golang.org/x/crypto/openpgp", "github.com/docker/docker"}
	for _, path := range []string{"golang.org/x/crypto/openpgp", "golang.org/x/crypto/openpgp/packet", "github.com/docker/docker/client [test]"} {
		if !forbiddenPackage(path, prefixes) {
			t.Errorf("unsafe path allowed: %s", path)
		}
	}
	for _, path := range []string{"golang.org/x/crypto/sha3", "github.com/docker/dockerish"} {
		if forbiddenPackage(path, prefixes) {
			t.Errorf("unrelated path rejected: %s", path)
		}
	}
}
func TestP0RunnerStaysStandardLibraryOnly(t *testing.T) {
	if !importAllowed("tools/p0/main.go", "os/exec", false) {
		t.Fatal("runner cannot start isolated services")
	}
	for _, path := range []string{"github.com/jackc/pgx/v5", modulePath + "/internal/services/tokens", modulePath + "/internal/app"} {
		if importAllowed("tools/p0/main.go", path, false) {
			t.Fatalf("runner imported application/dependency code: %s", path)
		}
	}
}
