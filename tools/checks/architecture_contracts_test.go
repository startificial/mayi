package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchitectureContracts(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "pure URL parsing in domain",
			files: map[string]string{"internal/domain/clients/redirect.go": `package clients; import "net/url"; func Valid(raw string) bool { _,err:=url.Parse(raw);return err==nil }`},
		},
		{
			name:  "URL parsing does not permit HTTP I/O",
			files: map[string]string{"internal/domain/clients/redirect.go": `package clients; import "net/http"; func Fetch(raw string) { http.Get(raw) }`},
			want:  "forbidden import",
		},
		{
			name:  "URL parsing does not permit sockets",
			files: map[string]string{"internal/domain/clients/redirect.go": `package clients; import "net"; func Fetch(raw string) { net.Dial("tcp",raw) }`},
			want:  "forbidden import",
		},
		{
			name: "consumer owned port and adapter assertion",
			files: map[string]string{
				"internal/services/tokens/ports.go":   `package tokens; type Signer interface { Sign([]byte) ([]byte, error) }`,
				"internal/services/tokens/service.go": `package tokens; type Service struct { signer Signer }; func New(s Signer) *Service { return &Service{signer:s} }`,
				"internal/adapters/outbound/crypto/signer.go": `package crypto
import "github.com/startificial/mayi/internal/services/tokens"
type Signer struct{}
func (*Signer) Sign(b []byte) ([]byte,error) { return b,nil }
var _ tokens.Signer = (*Signer)(nil)
func New() *Signer { return &Signer{} }`,
				"internal/app/app.go": `package app
import "github.com/startificial/mayi/internal/services/tokens"
import "github.com/startificial/mayi/internal/adapters/outbound/crypto"
func Build() *tokens.Service { return tokens.New(crypto.New()) }`,
			},
		},
		{
			name:  "port in wrong file",
			files: map[string]string{"internal/services/tokens/service.go": `package tokens; type Store interface { Save() error }`},
			want:  "consumer-owned ports.go",
		},
		{
			name:  "inline port in wrong file",
			files: map[string]string{"internal/services/tokens/service.go": `package tokens; type Service struct { store interface { Save() error } }`},
			want:  "consumer-owned ports.go",
		},
		{
			name:  "adapter owned port",
			files: map[string]string{"internal/adapters/outbound/postgres/store.go": `package postgres; type Store interface { Save() error }`},
			want:  "not export their own interfaces",
		},
		{
			name:  "adapter missing assertion",
			files: map[string]string{"internal/adapters/outbound/postgres/store.go": `package postgres; type Store struct{}`},
			want:  "adapter root needs a static conformance assertion",
		},
		{
			name: "adapter assertion against concrete service type",
			files: map[string]string{
				"internal/services/tokens/ports.go":           `package tokens; type Signer struct{}`,
				"internal/adapters/outbound/crypto/signer.go": `package crypto; import "github.com/startificial/mayi/internal/services/tokens"; type Signer struct{}; var _ tokens.Signer = (*Signer)(nil)`,
			},
			want: "adapter root needs a static conformance assertion",
		},
		{
			name: "global service locator",
			files: map[string]string{
				"internal/services/grants/ports.go":   `package grants; type Store interface { Save() error }`,
				"internal/services/grants/service.go": `package grants; var GlobalStore Store`,
			},
			want: "package-level runtime state",
		},
		{
			name:  "blank variable cannot hide initialization",
			files: map[string]string{"internal/domain/grants/grant.go": `package grants; func setup() int { return 1 }; var _ = setup()`},
			want:  "package-level runtime state",
		},
		{
			name:  "sentinel error allowed",
			files: map[string]string{"internal/domain/grants/grant.go": `package grants; import errlib "errors"; var ErrRevoked = errlib.New("revoked")`},
		},
		{
			name:  "init side effect",
			files: map[string]string{"internal/services/grants/service.go": `package grants; func init() {}`},
			want:  "init is forbidden",
		},
		{
			name:  "aliased ambient clock reference",
			files: map[string]string{"internal/domain/grants/grant.go": `package grants; import clock "time"; func expiry() clock.Time { now := clock.Now; return now() }`},
			want:  "ambient effect time.Now",
		},
		{
			name:  "explicit time value allowed",
			files: map[string]string{"internal/domain/grants/grant.go": `package grants; import "time"; func expiry(now time.Time) time.Time { return now.Add(time.Minute) }`},
		},
		{
			name:  "shadowing import is not clock call",
			files: map[string]string{"internal/domain/grants/grant.go": `package grants; import "time"; type Clock struct{}; func (Clock) Now() int { return 0 }; func check(now time.Time) int { time := Clock{}; return time.Now() }`},
		},
		{
			name:  "tagged clock checked",
			files: map[string]string{"internal/services/grants/clock_windows.go": "//go:build windows\n\npackage grants\nimport \"time\"\nfunc Now() time.Time { return time.Now() }"},
			want:  "ambient effect time.Now",
		},
		{
			name:  "generated code checked",
			files: map[string]string{"internal/domain/grants/generated.go": "// Code generated. DO NOT EDIT.\npackage grants\nimport \"time\"\nfunc Now() time.Time { return time.Now() }"},
			want:  "ambient effect time.Now",
		},
		{
			name:  "domain persistence tag",
			files: map[string]string{"internal/domain/grants/grant.go": "package grants; type Grant struct { ID string `db:\"id\"` }"},
			want:  "wire/persistence tags",
		},
		{
			name:  "service wire tag",
			files: map[string]string{"internal/services/grants/commands.go": "package grants; type Revoke struct { ID string `json:\"id\"` }"},
			want:  "wire/persistence tags",
		},
		{
			name:  "inbound wire DTO allowed",
			files: map[string]string{"internal/adapters/inbound/http/admin/dto.go": "package admin; type Revoke struct { ID string `json:\"id\"` }"},
		},
		{
			name: "handler constructing services",
			files: map[string]string{
				"internal/services/grants/service.go":             `package grants; type Service struct{}; func New() *Service { return &Service{} }`,
				"internal/adapters/inbound/http/admin/handler.go": `package admin; import "github.com/startificial/mayi/internal/services/grants"; func handle() { _ = grants.New() }`,
			},
			want: "constructors may only be wired",
		},
		{
			name: "SDK private state is allowed",
			files: map[string]string{
				"internal/domain/identity/subject.go": `package identity; type Subject string`,
				"pkg/resource/client.go":              `package resource; import "github.com/startificial/mayi/internal/domain/identity"; type Client struct { subject identity.Subject }; type Principal struct { ID string }; func (c *Client) Principal() Principal { return Principal{ID:string(c.subject)} }`,
			},
		},
		{
			name: "SDK exported field leaks internal type",
			files: map[string]string{
				"internal/domain/identity/subject.go": `package identity; type Subject string`,
				"pkg/resource/client.go":              `package resource; import "github.com/startificial/mayi/internal/domain/identity"; type Principal struct { ID identity.Subject }`,
			},
			want: "public SDK API exposes an internal type",
		},
		{
			name: "SDK alias leak across files",
			files: map[string]string{
				"internal/domain/identity/subject.go": `package identity; type Subject string`,
				"pkg/resource/private.go":             `package resource; import id "github.com/startificial/mayi/internal/domain/identity"; type hidden = id.Subject`,
				"pkg/resource/client.go":              `package resource; func Subject() hidden { return "" }`,
			},
			want: "public SDK API exposes an internal type",
		},
		{
			name: "SDK parameter name not confused for type",
			files: map[string]string{
				"internal/domain/identity/subject.go": `package identity; type Subject string`,
				"pkg/resource/client.go":              `package resource; import id "github.com/startificial/mayi/internal/domain/identity"; type hidden = id.Subject; func Subject(hidden string) string { return hidden }`,
			},
		},
		{
			name: "SDK default package name different from directory",
			files: map[string]string{
				"internal/domain/identity/subject.go": `package identities; type Subject string`,
				"pkg/resource/client.go":              `package resource; import "github.com/startificial/mayi/internal/domain/identity"; func Subject() identities.Subject { return "" }`,
			},
			want: "public SDK API exposes an internal type",
		},
		{
			name:  "dot import bypass",
			files: map[string]string{"internal/domain/grants/grant.go": `package grants; import . "time"; func expiry() Time { return Now() }`},
			want:  "dot imports",
		},
		{
			name:  "side effect import bypass",
			files: map[string]string{"internal/services/grants/service.go": `package grants; import _ "time"`},
			want:  "side-effect imports",
		},
		{
			name:  "linkname bypass",
			files: map[string]string{"internal/domain/grants/grant.go": "package grants\n//go:linkname inject hidden.func\nfunc inject()\n"},
			want:  "go:linkname bypasses",
		},
		{
			name: "test fixtures cannot supply production imports",
			files: map[string]string{
				"internal/services/grants/service.go":       `package grants; import _ "github.com/startificial/mayi/internal/domain/testdata/hidden"`,
				"internal/domain/testdata/hidden/hidden.go": `package hidden`,
			},
			want: "fixture-only package",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range tc.files {
				writeFixture(t, root, name, content)
			}
			err := checkArchitecture(root)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestSDKTransitiveBoundary(t *testing.T) {
	graph := map[string]map[string]bool{
		"pkg/resource":                     {"internal/services/resource": true},
		"internal/services/resource":       {"internal/services/administration": true},
		"internal/services/administration": {"internal/domain/identity": true},
		"internal/domain/identity":         {},
	}
	failures := checkLocalGraph(graph)
	if len(failures) != 1 || !strings.Contains(failures[0].Error(), "pkg/resource -> internal/services/resource -> internal/services/administration") {
		t.Fatalf("expected traced transitive violation, got %v", failures)
	}
}

func TestArchitectureInfrastructurePatterns(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name: "generated infrastructure interface stays in adapter family",
			files: map[string]string{
				"internal/services/grants/ports.go":                   `package grants; type Reader interface { Read() error }`,
				"internal/adapters/outbound/postgres/store.go":        `package postgres; import "github.com/startificial/mayi/internal/services/grants"; type Store struct{}; var _ grants.Reader = (*Store)(nil)`,
				"internal/adapters/outbound/postgres/generated/db.go": `package generated; type DBTX interface { Exec() error }`,
			},
		},
		{
			name:  "embedded string assets allowed",
			files: map[string]string{"internal/adapters/inbound/web/assets.go": "package web\nimport _ \"embed\"\n//go:embed login.html\nvar login string\n"},
		},
		{
			name:  "embedded filesystem allowed",
			files: map[string]string{"internal/adapters/inbound/web/assets.go": "package web\nimport \"embed\"\n//go:embed *.html\nvar pages embed.FS\n"},
		},
		{
			name:  "embedded mutable data rejected",
			files: map[string]string{"internal/adapters/inbound/web/assets.go": "package web\nimport _ \"embed\"\n//go:embed login.html\nvar login []byte\n"},
			want:  "package-level runtime state",
		},
		{
			name:  "builtin output rejected",
			files: map[string]string{"internal/domain/grants/grant.go": `package grants; func report() { println("hello") }`},
			want:  "builtin output",
		},
		{
			name:  "template file method rejected",
			files: map[string]string{"internal/adapters/inbound/web/template.go": `package web; import "html/template"; func render() { tmpl := template.New("page"); _,_ = tmpl.ParseFiles("file.html") }`},
			want:  "file-backed template loading",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range tc.files {
				writeFixture(t, root, name, content)
			}
			err := checkArchitecture(root)
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestArchitectureCycleIncludesTaggedSource(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "internal/domain/one/one_linux.go", "//go:build linux\n\npackage one\nimport _ \"github.com/startificial/mayi/internal/domain/two\"\n")
	writeFixture(t, root, "internal/domain/two/two_windows.go", "//go:build windows\n\npackage two\nimport _ \"github.com/startificial/mayi/internal/domain/one\"\n")
	if err := checkArchitecture(root); err == nil || !strings.Contains(err.Error(), "production import cycle") {
		t.Fatalf("expected conservative union-graph cycle failure, got %v", err)
	}
}

func TestProductionSourceSymlinkRejected(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	writeFixture(t, out, "hidden.go", "package hidden")
	if err := os.MkdirAll(filepath.Join(root, "internal/domain/grants"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(out, "hidden.go"), filepath.Join(root, "internal/domain/grants/grant.go")); err != nil {
		t.Fatal(err)
	}
	if err := checkArchitecture(root); err == nil || !strings.Contains(err.Error(), "symlinks in production source") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestPortConformanceIsCheckedByCompiler(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module "+modulePath+"\n\ngo 1.27.0\n")
	writeFixture(t, root, "internal/services/tokens/ports.go", `package tokens
type Signer interface { Sign([]byte) ([]byte, error) }
`)
	const adapter = `package signing
import "github.com/startificial/mayi/internal/services/tokens"
type Signer struct{}
var _ tokens.Signer = (*Signer)(nil)
`
	path := "internal/adapters/outbound/signing/signer.go"
	writeFixture(t, root, path, adapter+`func (*Signer) Sign(data []byte) ([]byte,error) { return data,nil }`)
	if err := checkArchitecture(root); err != nil {
		t.Fatal(err)
	}
	if _, err := runGo(root, "test", "./..."); err != nil {
		t.Fatalf("valid port implementation must compile: %v", err)
	}
	writeFixture(t, root, path, adapter)
	if _, err := runGo(root, "test", "./..."); err == nil || !strings.Contains(err.Error(), "does not implement") {
		t.Fatalf("compiler must reject a missing port method: %v", err)
	}
}
