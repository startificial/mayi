package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type declaredType struct {
	source *architectureSource
	spec   *ast.TypeSpec
}

type typeIndex map[string][]declaredType

func checkArchitectureContracts(sources []*architectureSource, positions *token.FileSet) []error {
	var failures []error
	report := func(source *architectureSource, node ast.Node, message string) {
		failures = append(failures, fmt.Errorf("%s:%d: %s", source.path, positions.Position(node.Pos()).Line, message))
	}
	types := make(typeIndex)
	graph := make(map[string]map[string]bool)
	families := make(map[string]bool)
	for _, source := range sources {
		if source.test {
			continue
		}
		graph[source.pkg] = nonNilEdges(graph[source.pkg])
		for _, imported := range source.imports {
			if strings.HasPrefix(imported, modulePath+"/") {
				graph[source.pkg][strings.TrimPrefix(imported, modulePath+"/")] = true
			}
		}
		if family := adapterFamily(source.pkg); family != "" {
			if _, ok := families[family]; !ok {
				families[family] = false
			}
		}
		for _, decl := range source.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				key := source.pkg + "." + typeSpec.Name.Name
				types[key] = append(types[key], declaredType{source, typeSpec})
			}
		}
	}
	for _, source := range sources {
		if source.test || !isProduction(source.path) {
			continue
		}
		for _, comments := range source.file.Comments {
			for _, comment := range comments.List {
				if strings.HasPrefix(comment.Text, "//go:linkname") {
					report(source, comment, "go:linkname bypasses package boundaries")
				}
			}
		}
		for _, decl := range source.file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
				report(source, fn, "init is forbidden; inject dependencies explicitly at the composition root")
			}
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				if !safePackageVariable(source, value) && !embeddedAsset(source, gen, value) {
					report(source, value, "package-level runtime state is forbidden; use constructor-injected fields (sentinel errors and static conformance assertions are allowed)")
				}
				if family := adapterFamily(source.pkg); family == source.pkg && family != "" && isConformanceAssertion(value) {
					if selector, ok := value.Type.(*ast.SelectorExpr); ok {
						if id, ok := selector.X.(*ast.Ident); ok {
							owner := strings.TrimPrefix(source.imports[id.Name], modulePath+"/")
							for _, port := range types[owner+"."+selector.Sel.Name] {
								if _, ok := port.spec.Type.(*ast.InterfaceType); ok && within(owner, "internal/services") {
									families[family] = true
								}
							}
						}
					}
				}
			}
		}
		ast.Inspect(source.file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.InterfaceType:
				if within(source.pkg, "internal/services") && n.Methods.NumFields() > 0 && !isPortsFile(source.path) {
					report(source, n, "service interfaces belong in consumer-owned ports.go or ports_<variant>.go")
				}
			case *ast.TypeSpec:
				if adapterFamily(source.pkg) == source.pkg && n.Name.IsExported() {
					if _, ok := n.Type.(*ast.InterfaceType); ok {
						report(source, n, "outbound adapters must implement consumer-owned ports, not export their own interfaces")
					}
				}
			case *ast.Field:
				if n.Tag != nil && (within(source.pkg, "internal/domain") || within(source.pkg, "internal/services")) {
					text, _ := strconv.Unquote(n.Tag.Value)
					for _, key := range []string{"json", "xml", "yaml", "db", "gorm", "bson", "sql", "form", "query", "header", "validate", "binding"} {
						if _, ok := reflect.StructTag(text).Lookup(key); ok {
							report(source, n, "wire/persistence tags belong in adapter DTOs, not domain or service types: "+key)
						}
					}
				}
			case *ast.CallExpr:
				if id, ok := n.Fun.(*ast.Ident); ok && id.Obj == nil && isPureLayer(source.path) && (id.Name == "print" || id.Name == "println") {
					report(source, n, "builtin output is an ambient effect; inject an output/telemetry port")
				}
			case *ast.SelectorExpr:
				if isPureLayer(source.path) && (n.Sel.Name == "ParseFiles" || n.Sel.Name == "ParseGlob") {
					report(source, n, "file-backed template loading belongs in composition, not pure layers")
				}
				id, ok := n.X.(*ast.Ident)
				if !ok {
					break
				}
				// Parser resolution avoids treating a shadowing local variable as an import.
				if id.Obj != nil {
					break
				}
				imported := source.imports[id.Name]
				if isPureLayer(source.path) && forbiddenPureSelector(imported, n.Sel.Name) {
					report(source, n, "ambient effect "+imported+"."+n.Sel.Name+" must be supplied through a port or explicit value")
				}
				local := strings.TrimPrefix(imported, modulePath+"/")
				if (n.Sel.Name == "New" || n.Sel.Name == "NewService") && (within(local, "internal/services") || within(local, "internal/adapters/outbound")) {
					ownAdapter := adapterFamily(source.pkg) != "" && adapterFamily(source.pkg) == adapterFamily(local)
					if !within(source.pkg, "internal/app") && !within(source.pkg, "pkg/resource") && !ownAdapter {
						report(source, n, "service/adapter constructors may only be wired in internal/app, the bounded resource SDK, or their own adapter family")
					}
				}
			}
			return true
		})
		if within(source.pkg, "pkg/resource") {
			checkSDKExports(source, types, func(node ast.Node) {
				report(source, node, "public SDK API exposes an internal type; map to an SDK-owned contract")
			})
		}
	}
	for _, family := range sortedKeys(families) {
		if !families[family] {
			failures = append(failures, fmt.Errorf("%s: adapter root needs a static conformance assertion against an interface declared in internal/services", family))
		}
	}
	failures = append(failures, checkLocalGraph(graph)...)
	return failures
}

func nonNilEdges(edges map[string]bool) map[string]bool {
	if edges == nil {
		return make(map[string]bool)
	}
	return edges
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func adapterFamily(path string) string {
	const prefix = "internal/adapters/outbound/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	return prefix + strings.Split(strings.TrimPrefix(path, prefix), "/")[0]
}

func isPortsFile(path string) bool {
	base := filepath.Base(path)
	return base == "ports.go" || (strings.HasPrefix(base, "ports_") && strings.HasSuffix(base, ".go"))
}

func isConformanceAssertion(spec *ast.ValueSpec) bool {
	if len(spec.Names) != 1 || spec.Names[0].Name != "_" || spec.Type == nil || len(spec.Values) != 1 {
		return false
	}
	switch value := spec.Values[0].(type) {
	case *ast.CallExpr:
		if len(value.Args) != 1 {
			return false
		}
		nilValue, ok := value.Args[0].(*ast.Ident)
		if !ok || nilValue.Name != "nil" {
			return false
		}
		paren, ok := value.Fun.(*ast.ParenExpr)
		if !ok {
			return false
		}
		pointer, ok := paren.X.(*ast.StarExpr)
		if !ok {
			return false
		}
		_, ok = pointer.X.(*ast.Ident)
		return ok
	case *ast.CompositeLit:
		_, localType := value.Type.(*ast.Ident)
		return localType && len(value.Elts) == 0
	}
	return false
}

func safePackageVariable(source *architectureSource, spec *ast.ValueSpec) bool {
	if isConformanceAssertion(spec) {
		return true
	}
	if len(spec.Names) != 1 || len(spec.Values) != 1 {
		return false
	}
	call, ok := spec.Values[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := selector.X.(*ast.Ident)
	literal, literalOK := call.Args[0].(*ast.BasicLit)
	return ok && literalOK && literal.Kind == token.STRING && source.imports[id.Name] == "errors" && selector.Sel.Name == "New"
}

func forbiddenPureSelector(imported, name string) bool {
	var names string
	switch imported {
	case "time":
		names = " Now Since Until Sleep After AfterFunc Tick NewTicker NewTimer LoadLocation Local "
	case "fmt":
		names = " Print Println Printf Scan Scanln Scanf "
	case "html/template", "text/template":
		names = " ParseFiles ParseGlob "
	}
	return strings.Contains(names, " "+name+" ")
}

// Embedded assets are build-time data, not runtime dependency initialization.
// Keep them unexported and read-only (string or embed.FS, never mutable []byte).
func embeddedAsset(source *architectureSource, decl *ast.GenDecl, spec *ast.ValueSpec) bool {
	if (!within(source.pkg, "internal/app") && !within(source.pkg, "internal/adapters/inbound/web")) || len(spec.Names) != 1 || spec.Names[0].IsExported() || len(spec.Values) != 0 {
		return false
	}
	directive := false
	for _, comments := range []*ast.CommentGroup{decl.Doc, spec.Doc} {
		if comments != nil {
			for _, comment := range comments.List {
				directive = directive || strings.HasPrefix(comment.Text, "//go:embed ")
			}
		}
	}
	if !directive {
		return false
	}
	if id, ok := spec.Type.(*ast.Ident); ok {
		return id.Name == "string"
	}
	if selector, ok := spec.Type.(*ast.SelectorExpr); ok {
		if id, ok := selector.X.(*ast.Ident); ok {
			return source.imports[id.Name] == "embed" && selector.Sel.Name == "FS"
		}
	}
	return false
}

func checkLocalGraph(graph map[string]map[string]bool) []error {
	var failures []error
	for _, start := range sortedKeys(graph) {
		if !isProduction(start) {
			continue
		}
		visited := make(map[string]bool)
		var visit func(string, []string)
		visit = func(current string, chain []string) {
			for _, next := range sortedKeys(graph[current]) {
				path := append(append([]string(nil), chain...), next)
				if next == start {
					failures = append(failures, fmt.Errorf("production import cycle: %s", strings.Join(path, " -> ")))
					continue
				}
				if visited[next] {
					continue
				}
				visited[next] = true
				if _, exists := graph[next]; !exists {
					failures = append(failures, fmt.Errorf("production import references missing or fixture-only package: %s", strings.Join(path, " -> ")))
					continue
				}
				if within(start, "pkg/resource") && !importAllowed(start, modulePath+"/"+next, false) {
					failures = append(failures, fmt.Errorf("SDK transitive boundary violation: %s", strings.Join(path, " -> ")))
				}
				visit(next, path)
			}
		}
		visit(start, []string{start})
	}
	return failures
}

func checkSDKExports(source *architectureSource, types typeIndex, report func(ast.Node)) {
	var leaks func(ast.Expr, *architectureSource, map[string]bool) bool
	leaks = func(expr ast.Expr, owner *architectureSource, seen map[string]bool) bool {
		found := false
		ast.Inspect(expr, func(node ast.Node) bool {
			if found || node == nil {
				return false
			}
			switch n := node.(type) {
			case *ast.Field:
				// Inspect parameter/field types, never their names or tags.
				found = leaks(n.Type, owner, seen)
				return false
			case *ast.StructType:
				for _, field := range n.Fields.List {
					exported := len(field.Names) == 0
					for _, name := range field.Names {
						exported = exported || name.IsExported()
					}
					if exported && leaks(field.Type, owner, seen) {
						found = true
					}
				}
				return false
			case *ast.SelectorExpr:
				if id, ok := n.X.(*ast.Ident); ok {
					local := strings.TrimPrefix(owner.imports[id.Name], modulePath+"/")
					if within(local, "internal") {
						found = true
					} else if within(local, "pkg/resource") {
						key := local + "." + n.Sel.Name
						if !seen[key] {
							seen[key] = true
							for _, target := range types[key] {
								found = found || leaks(target.spec.Type, target.source, seen)
							}
						}
					}
				}
				return false
			case *ast.Ident:
				key := owner.pkg + "." + n.Name
				if !seen[key] {
					seen[key] = true
					for _, target := range types[key] {
						found = found || leaks(target.spec.Type, target.source, seen)
					}
				}
			}
			return true
		})
		return found
	}
	for _, decl := range source.file.Decls {
		switch n := decl.(type) {
		case *ast.FuncDecl:
			if n.Name.IsExported() && leaks(n.Type, source, make(map[string]bool)) {
				report(n)
			}
		case *ast.GenDecl:
			if n.Tok == token.TYPE {
				for _, spec := range n.Specs {
					t := spec.(*ast.TypeSpec)
					if t.Name.IsExported() && (leaks(t.Type, source, make(map[string]bool)) || (t.TypeParams != nil && leaks(&ast.FuncType{Params: t.TypeParams}, source, make(map[string]bool)))) {
						report(t)
					}
				}
			}
			if n.Tok == token.CONST || n.Tok == token.VAR {
				for _, spec := range n.Specs {
					value := spec.(*ast.ValueSpec)
					exported := false
					for _, name := range value.Names {
						exported = exported || name.IsExported()
					}
					if !exported {
						continue
					}
					if value.Type != nil {
						if leaks(value.Type, source, make(map[string]bool)) {
							report(value)
						}
					} else {
						for _, expression := range value.Values {
							if leaks(expression, source, make(map[string]bool)) {
								report(value)
								break
							}
						}
					}
				}
			}
		}
	}
}
