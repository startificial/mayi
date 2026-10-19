package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

const modulePath = "github.com/startificial/mayi"

func within(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func sourceLayer(path string) string {
	for _, prefix := range []string{
		"internal/domain", "internal/services", "internal/adapters/inbound/web",
		"internal/adapters/inbound", "internal/adapters/outbound", "internal/app",
		"cmd/mayi", "pkg/resource", "tools/checks", "tools/p0", "tests", "examples",
	} {
		if within(path, prefix) {
			return prefix
		}
	}
	return ""
}

// The core is deliberately pure. Concrete crypto and I/O belong behind ports.
func effectfulImport(path string) bool {
	// net/url parses values; it cannot open sockets or perform network I/O.
	if path == "net/url" {
		return false
	}
	for _, prefix := range []string{
		"net", "database", "os", "syscall", "unsafe", "plugin", "runtime/cgo",
		"io/ioutil", "log", "crypto/rand", "math/rand", "reflect", "runtime", "testing",
	} {
		if within(path, prefix) {
			return true
		}
	}
	return false
}

func importAllowed(source, imported string, test bool) bool {
	layer := sourceLayer(source)
	if layer == "" {
		return false
	}
	local := strings.TrimPrefix(imported, modulePath+"/")
	isLocal := local != imported
	if within(source, "examples/bff/services") && !test {
		if !isLocal {
			return !strings.Contains(strings.Split(imported, "/")[0], ".") && !effectfulImport(imported)
		}
		return within(local, "examples/bff/services") || within(local, "examples/bff/domain")
	}
	if within(source, "examples/bff") && isLocal && within(local, "internal") {
		return false
	}
	if !isLocal {
		external := strings.Contains(strings.Split(imported, "/")[0], ".") || imported == "C"
		switch layer {
		case "internal/domain", "internal/services", "internal/adapters/inbound/web", "tools/checks", "tools/p0", "cmd/mayi", "pkg/resource":
			if external {
				return false
			}
		}
		if !test && (layer == "internal/domain" || layer == "internal/services" || layer == "internal/adapters/inbound/web") {
			return !effectfulImport(imported)
		}
		if (layer == "internal/adapters/inbound" || layer == "pkg/resource" || layer == "cmd/mayi") && within(imported, "database") {
			return false
		}
		// Only protocol integration libraries are admitted directly into inbound adapters.
		if layer == "internal/adapters/inbound" {
			if external && !within(imported, "github.com/ory/fosite") && !within(imported, "github.com/zitadel/oidc") {
				return false
			}
		}
		return true
	}
	if strings.Contains(local, "/testdata/") || within(local, "tests") || within(local, "tools") || within(local, "examples") {
		return layer == "tests" || layer == "examples" || (test && layer == "tools/checks")
	}
	switch layer {
	case "internal/domain":
		return within(local, "internal/domain")
	case "internal/services":
		return within(local, "internal/domain") || within(local, "internal/services")
	case "internal/adapters/inbound/web":
		return within(local, "internal/adapters/inbound/web")
	case "internal/adapters/inbound":
		return within(local, "internal/domain") || within(local, "internal/services") || within(local, "internal/adapters/inbound")
	case "internal/adapters/outbound":
		return within(local, "internal/domain") || within(local, "internal/services") || within(local, "internal/adapters/outbound")
	case "internal/app":
		return within(local, "internal") && sourceLayer(local) != ""
	case "cmd/mayi":
		return within(local, "internal/app")
	case "pkg/resource":
		return within(local, "pkg/resource") || within(local, "internal/domain") || within(local, "internal/services/resource") || within(local, "internal/adapters/outbound/status") || within(local, "internal/adapters/outbound/crypto") || within(local, "internal/adapters/outbound/egress/httpclient")
	case "tests", "examples":
		return sourceLayer(local) != ""
	case "tools/checks":
		return within(local, "tools/checks")
	case "tools/p0":
		return false // Service runner is standard-library-only, with no application imports.
	}
	return false
}

func checkArchitecture(root string) error {
	var failures []error
	var sources []*architectureSource
	positions := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "testdata") {
			return filepath.SkipDir
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			rel, _ := filepath.Rel(root, path)
			if within(filepath.ToSlash(rel), "internal") || within(filepath.ToSlash(rel), "pkg") || within(filepath.ToSlash(rel), "cmd") {
				failures = append(failures, fmt.Errorf("%s: symlinks in production source can bypass architecture checks", rel))
			}
			return nil
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if sourceLayer(rel) == "" {
			failures = append(failures, fmt.Errorf("%s: Go source outside canonical layout", rel))
			return nil
		}
		file, err := parser.ParseFile(positions, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		source := &architectureSource{path: rel, pkg: filepath.ToSlash(filepath.Dir(rel)), file: file, imports: make(map[string]string), test: strings.HasSuffix(rel, "_test.go")}
		sources = append(sources, source)
		for _, imp := range file.Imports {
			value, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if !importAllowed(rel, value, strings.HasSuffix(rel, "_test.go")) {
				failures = append(failures, fmt.Errorf("%s: forbidden import %s", rel, value))
			}
			alias := filepath.Base(value)
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			source.imports[alias] = value
			embedImport := value == "embed" && within(source.pkg, "internal/adapters/inbound/web")
			if !source.test && isProduction(rel) && (alias == "." || (alias == "_" && isPureLayer(rel) && !embedImport)) {
				failures = append(failures, fmt.Errorf("%s: dot imports and side-effect imports in pure layers are forbidden", rel))
			}
		}
		return nil
	})
	if err != nil {
		failures = append(failures, err)
	}
	// Correct default import names for local packages whose name differs from their directory.
	names := make(map[string]string)
	for _, source := range sources {
		if !source.test {
			names[modulePath+"/"+source.pkg] = source.file.Name.Name
		}
	}
	for _, source := range sources {
		for _, imp := range source.file.Imports {
			value, _ := strconv.Unquote(imp.Path.Value)
			if imp.Name == nil && names[value] != "" && names[value] != filepath.Base(value) {
				delete(source.imports, filepath.Base(value))
				source.imports[names[value]] = value
			}
		}
	}
	failures = append(failures, checkArchitectureContracts(sources, positions)...)
	return errors.Join(failures...)
}

type architectureSource struct {
	path, pkg string
	file      *ast.File
	imports   map[string]string
	test      bool
}

func isProduction(path string) bool {
	return within(path, "internal") || within(path, "cmd") || within(path, "pkg") || within(path, "examples/bff")
}

func isPureLayer(path string) bool {
	layer := sourceLayer(path)
	return layer == "internal/domain" || layer == "internal/services" || layer == "internal/adapters/inbound/web" || within(path, "examples/bff/services") || within(path, "examples/bff/domain")
}
