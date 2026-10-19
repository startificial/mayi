// Package conformance checks traceability of the local preview evidence. These
// tests are not a replacement for the referenced integration runs/certification.
package conformance_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestP2EvidenceReferencesExecutableChecksAndPinnedStandards(t *testing.T) {
	data, err := os.ReadFile("p2-evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Version        int    `json:"version"`
		Phase          string `json:"phase"`
		Profile        string `json:"profile"`
		Certified      bool   `json:"certified"`
		Specifications []struct {
			ID, Revision string
			Sections     []string
		}
		Groups []struct {
			Capability   string
			Requirements []string
			Checks       []struct{ Path, Test string }
		}
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Version != 1 || manifest.Phase != "P2" || manifest.Certified || len(manifest.Groups) < 7 {
		t.Fatal("invalid preview evidence manifest")
	}
	pins, err := os.ReadFile("../../specs/manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var baseline struct {
		Documents []struct {
			ID, Revision string
			Implemented  []string `json:"implemented_sections"`
		}
	}
	if json.Unmarshal(pins, &baseline) != nil {
		t.Fatal("invalid specification pins")
	}
	for _, spec := range manifest.Specifications {
		found := false
		for _, pin := range baseline.Documents {
			if spec.ID == pin.ID && spec.Revision == pin.Revision {
				found = true
				for _, section := range spec.Sections {
					matched := false
					for _, implemented := range pin.Implemented {
						if section == implemented {
							matched = true
						}
					}
					if !matched {
						t.Fatal("section evidence drift", spec.ID, section)
					}
				}
			}
		}
		if !found {
			t.Fatal("unreviewed specification revision", spec.ID)
		}
	}
	ids := map[string]bool{}
	for _, group := range manifest.Groups {
		if group.Capability == "" || len(group.Checks) == 0 || len(group.Requirements) == 0 {
			t.Fatal("empty evidence group")
		}
		for _, id := range group.Requirements {
			if ids[id] {
				t.Fatal("duplicate requirement", id)
			}
			ids[id] = true
		}
		for _, check := range group.Checks {
			if filepath.IsAbs(check.Path) || filepath.Clean(check.Path) != check.Path || strings.HasPrefix(check.Path, "../") || !strings.HasSuffix(check.Path, "_test.go") {
				t.Fatal("invalid evidence path", check.Path)
			}
			source, err := parser.ParseFile(token.NewFileSet(), filepath.Join("../..", check.Path), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, declaration := range source.Decls {
				if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == check.Test && function.Recv == nil {
					found = true
				}
			}
			if !found {
				t.Fatal("evidence test does not exist", check.Path, check.Test)
			}
		}
	}
}
