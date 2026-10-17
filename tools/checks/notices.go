package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Module source is served as an immutable Go module archive. Modified sources
// require a separate source-aware admission implementation; replaces are denied.
func moduleArchiveURL(name, version string) string {
	return "https://proxy.golang.org/" + escapeModuleIdentifier(name) + "/@v/" + escapeModuleIdentifier(version) + ".zip"
}

func escapeModuleIdentifier(value string) string {
	var escaped strings.Builder
	for _, c := range value {
		if c >= 'A' && c <= 'Z' {
			escaped.WriteByte('!')
			escaped.WriteRune(c + 'a' - 'A')
		} else {
			escaped.WriteRune(c)
		}
	}
	return escaped.String()
}

func validateMPLNotices(root string, modules []dependency) error {
	data, err := os.ReadFile(filepath.Join(root, "tools/license-evidence/MPL-2.0.txt"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != "3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04" {
		return fmt.Errorf("MPL-2.0 distribution license text changed")
	}
	notice, err := os.ReadFile(filepath.Join(root, "THIRD_PARTY_NOTICES.md"))
	if err != nil {
		return err
	}
	for _, dep := range modules {
		if !slices.Contains(dep.Licenses, "MPL-2.0") {
			continue
		}
		if dep.SourceAccess == nil || !strings.Contains(string(notice), dep.Name+"@"+dep.Version) || !strings.Contains(string(notice), dep.SourceAccess.URL) {
			return fmt.Errorf("%s: missing MPL source-access notice", dep.Name)
		}
	}
	return nil
}
