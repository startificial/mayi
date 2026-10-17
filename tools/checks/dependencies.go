package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type licensePolicy struct {
	Version int      `json:"version"`
	Allowed []string `json:"allowed"`
}

type evidenceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type dependency struct {
	Name     string         `json:"name"`
	Version  string         `json:"version"`
	Licenses []string       `json:"licenses"`
	Source   string         `json:"source"`
	Review   string         `json:"review"`
	Files    []evidenceFile `json:"files"`
}

type inventory struct {
	Version   int          `json:"version"`
	Toolchain dependency   `json:"toolchain"`
	Modules   []dependency `json:"modules"`
	Actions   []dependency `json:"actions"`
}

type goModule struct {
	Path    string
	Version string
	Main    bool
	Dir     string
	Replace *goModule
	Error   *struct{ Err string }
}

func readJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%s: trailing JSON content", path)
	}
	return nil
}

func validateEvidence(dep dependency, allowed map[string]bool, root string) error {
	if dep.Name == "" || dep.Version == "" || len(dep.Licenses) == 0 || len(dep.Files) == 0 || dep.Review == "" || !strings.HasPrefix(dep.Source, "https://") {
		return fmt.Errorf("%s: incomplete versioned license evidence", dep.Name)
	}
	for _, license := range dep.Licenses {
		if !allowed[license] {
			return fmt.Errorf("%s: disallowed or unknown license %q", dep.Name, license)
		}
	}
	for _, file := range dep.Files {
		if !filepath.IsLocal(file.Path) || len(file.SHA256) != sha256.Size*2 {
			return fmt.Errorf("%s: invalid evidence path or digest", dep.Name)
		}
		path := filepath.Join(root, filepath.FromSlash(file.Path))
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		absRoot, err = filepath.EvalSymlinks(absRoot)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(absRoot, resolved)
		if err != nil || !filepath.IsLocal(rel) {
			return fmt.Errorf("%s: evidence escapes its root", dep.Name)
		}
		data, err := os.ReadFile(resolved)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			return fmt.Errorf("%s: license evidence hash mismatch for %s", dep.Name, file.Path)
		}
	}
	return nil
}

func runGo(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out, nil
}

func validateModules(modules []goModule, approved []dependency, allowed map[string]bool) error {
	entries := make(map[string]dependency)
	for _, dep := range approved {
		key := dep.Name + "@" + dep.Version
		if _, exists := entries[key]; exists {
			return fmt.Errorf("duplicate module approval: %s", key)
		}
		entries[key] = dep
	}
	for _, mod := range modules {
		if mod.Error != nil {
			return fmt.Errorf("%s: %s", mod.Path, mod.Error.Err)
		}
		if mod.Replace != nil {
			return fmt.Errorf("%s: replacements need explicit source-aware license support; not permitted", mod.Path)
		}
		if mod.Main {
			if mod.Path != modulePath {
				return fmt.Errorf("unexpected root module %s", mod.Path)
			}
			continue
		}
		key := mod.Path + "@" + mod.Version
		dep, ok := entries[key]
		if !ok {
			return fmt.Errorf("unreviewed module %s: add exact-version license evidence", key)
		}
		if mod.Dir == "" {
			return fmt.Errorf("%s: source missing; run go mod download", key)
		}
		if err := validateEvidence(dep, allowed, mod.Dir); err != nil {
			return err
		}
		delete(entries, key)
	}
	if len(entries) != 0 {
		return fmt.Errorf("module inventory contains stale entries; remove approvals absent from the resolved graph")
	}
	return nil
}

var actionLine = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*(?:#.*)?$`)
var actionKey = regexp.MustCompile(`\buses\s*:|["']uses["']\s*:`)
var commitPin = regexp.MustCompile(`^[a-f0-9]{40}$`)

func validateActions(workflows []string, approved []dependency) error {
	entries := make(map[string]bool)
	for _, dep := range approved {
		if !commitPin.MatchString(dep.Version) {
			return fmt.Errorf("%s: action must use an immutable commit", dep.Name)
		}
		key := dep.Name + "@" + dep.Version
		if _, exists := entries[key]; exists {
			return fmt.Errorf("duplicate action approval: %s", key)
		}
		entries[key] = false
	}
	for _, workflow := range workflows {
		for _, line := range strings.Split(workflow, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || !actionKey.MatchString(line) {
				continue
			}
			match := actionLine.FindStringSubmatch(line)
			if match == nil {
				return fmt.Errorf("uses must be a literal unquoted block-YAML action reference: %s", line)
			}
			if _, ok := entries[match[1]]; !ok {
				return fmt.Errorf("unreviewed or unpinned action: %s", match[1])
			}
			entries[match[1]] = true
		}
	}
	for action, seen := range entries {
		if !seen {
			return fmt.Errorf("unused action approval: %s", action)
		}
	}
	return nil
}

func checkDependencies(root string) error {
	var policy licensePolicy
	var deps inventory
	if err := readJSON(filepath.Join(root, "tools/license-policy.json"), &policy); err != nil {
		return err
	}
	if err := readJSON(filepath.Join(root, "tools/dependencies.json"), &deps); err != nil {
		return err
	}
	if policy.Version != 1 || deps.Version != 1 || len(policy.Allowed) == 0 {
		return errors.New("unsupported or empty license policy/inventory")
	}
	allowed := make(map[string]bool)
	for _, license := range policy.Allowed {
		if allowed[license] {
			return fmt.Errorf("duplicate license %s", license)
		}
		allowed[license] = true
	}
	if deps.Toolchain.Name != "go" || runtime.Version() != deps.Toolchain.Version {
		return fmt.Errorf("Go toolchain mismatch: running %s, reviewed %s", runtime.Version(), deps.Toolchain.Version)
	}
	toolchainRoot := runtime.GOROOT()
	// Homebrew keeps LICENSE beside libexec; official Go archives keep it in GOROOT.
	if _, err := os.Stat(filepath.Join(toolchainRoot, "LICENSE")); os.IsNotExist(err) && filepath.Base(toolchainRoot) == "libexec" {
		toolchainRoot = filepath.Dir(toolchainRoot)
	}
	if err := validateEvidence(deps.Toolchain, allowed, toolchainRoot); err != nil {
		return err
	}
	var workflows []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "testdata") {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if entry.Name() == "vendor" || entry.Name() == "node_modules" {
				return fmt.Errorf("%s: untracked dependency tree is not supported by the license gate", rel)
			}
			return nil
		}
		switch entry.Name() {
		case "go.work", "go.work.sum", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "pyproject.toml", "Cargo.toml", "Dockerfile", "Containerfile", "action.yml", "action.yaml":
			return fmt.Errorf("%s: extend license inventory and checks for this dependency surface before introducing it", rel)
		case "go.mod":
			if rel != "go.mod" {
				return fmt.Errorf("%s: nested modules are not allowed", rel)
			}
		}
		if within(rel, ".github/workflows") && (filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			workflows = append(workflows, string(data))
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, action := range deps.Actions {
		if !strings.Contains(action.Source, "/"+action.Version+"/") {
			return fmt.Errorf("%s: license source must reference the reviewed commit", action.Name)
		}
		if err := validateEvidence(action, allowed, root); err != nil {
			return err
		}
	}
	if err := validateActions(workflows, deps.Actions); err != nil {
		return err
	}
	data, err := runGo(root, "list", "-mod=readonly", "-m", "-json", "all")
	if err != nil {
		return err
	}
	var modules []goModule
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var mod goModule
		if err := decoder.Decode(&mod); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		modules = append(modules, mod)
	}
	if len(modules) == 0 {
		return errors.New("empty module graph")
	}
	return validateModules(modules, deps.Modules, allowed)
}
