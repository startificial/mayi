package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

func forbiddenPackage(path string, prefixes []string) bool {
	path = strings.Split(path, " [")[0]
	for _, prefix := range prefixes {
		if within(path, prefix) {
			return true
		}
	}
	return false
}

// Some dependencies retain vulnerable, unused upstream test modules in their
// module graph. Keep them visible in inventory and forbid their package use.
// This is a reachability gate, not a substitute for fresh vulnerability review.
func checkCompiledPackages(root string) error {
	var policy struct {
		Version  int      `json:"version"`
		Prefixes []string `json:"prefixes"`
	}
	if err := readJSON(filepath.Join(root, "tools/forbidden-packages.json"), &policy); err != nil {
		return err
	}
	if policy.Version != 1 || len(policy.Prefixes) == 0 {
		return fmt.Errorf("empty forbidden-package policy")
	}
	data, err := runGo(root, "list", "-mod=readonly", "-deps", "-test", "-json", "./...")
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var pkg struct{ ImportPath string }
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if forbiddenPackage(pkg.ImportPath, policy.Prefixes) {
			return fmt.Errorf("known unsafe upstream package is reachable: %s", pkg.ImportPath)
		}
	}
	return nil
}
