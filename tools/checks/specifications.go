package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type specificationManifest struct {
	Version   int             `json:"version"`
	Documents []specification `json:"documents"`
}
type specification struct {
	ID                  string   `json:"id"`
	Revision            string   `json:"revision"`
	URL                 string   `json:"url"`
	ResolvedURL         string   `json:"resolved_url"`
	SHA256              string   `json:"sha256"`
	RetrievedOn         string   `json:"retrieved_on"`
	TargetPhase         string   `json:"target_phase"`
	TargetSections      []string `json:"target_sections"`
	ImplementedSections []string `json:"implemented_sections"`
	Deviations          []string `json:"deviations"`
}

// The .yaml file intentionally uses the JSON subset of YAML 1.2 so the gate
// needs no parser dependency. Hashes describe exact fetched bytes, not compliance.
func checkSpecifications(root string) error {
	var manifest specificationManifest
	if err := readJSON(filepath.Join(root, "specs/manifest.yaml"), &manifest); err != nil {
		return err
	}
	if manifest.Version != 1 || len(manifest.Documents) == 0 {
		return errors.New("missing specification baseline")
	}
	seen := make(map[string]bool)
	for _, spec := range manifest.Documents {
		if spec.ID == "" || seen[spec.ID] || spec.Revision == "" || len(spec.TargetSections) == 0 {
			return fmt.Errorf("%s: incomplete or duplicate specification pin", spec.ID)
		}
		seen[spec.ID] = true
		digest, err := hex.DecodeString(spec.SHA256)
		if err != nil || len(digest) != 32 {
			return fmt.Errorf("%s: invalid specification digest", spec.ID)
		}
		if _, err := time.Parse("2006-01-02", spec.RetrievedOn); err != nil {
			return fmt.Errorf("%s: invalid retrieval date", spec.ID)
		}
		if len(spec.TargetPhase) != 2 || spec.TargetPhase[0] != 'P' || spec.TargetPhase[1] < '0' || spec.TargetPhase[1] > '8' {
			return fmt.Errorf("%s: invalid target phase", spec.ID)
		}
		for _, raw := range []string{spec.URL, spec.ResolvedURL} {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pinnedSpecURL(u) {
				return fmt.Errorf("%s: source must use an immutable normative revision", spec.ID)
			}
		}
	}
	for _, id := range []string{"oauth21", "cimd", "id-jag", "rfc7636", "rfc8252", "rfc8414", "rfc9700", "rfc8707", "rfc9068", "rfc8725", "rfc9449", "rfc8693", "rfc7523", "rfc7009", "rfc7662", "rfc10017", "oidc-core", "oidc-discovery", "mcp-index", "mcp-authorization-server-discovery", "mcp-client-registration", "mcp-security-considerations", "mcp-enterprise"} {
		if !seen[id] {
			return fmt.Errorf("missing required specification %s", id)
		}
	}
	return nil
}
func pinnedSpecURL(u *url.URL) bool {
	switch u.Host {
	case "www.ietf.org":
		name := strings.TrimPrefix(u.Path, "/archive/id/")
		if name == u.Path || !strings.HasSuffix(name, ".txt") {
			return false
		}
		stem := strings.TrimSuffix(name, ".txt")
		i := strings.LastIndex(stem, "-")
		return i > 0 && len(stem[i+1:]) == 2 && stem[i+1] >= '0' && stem[i+1] <= '9' && stem[i+2] >= '0' && stem[i+2] <= '9'
	case "www.rfc-editor.org":
		name := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/rfc/rfc"), ".txt")
		if name == "" || u.Path != "/rfc/rfc"+name+".txt" {
			return false
		}
		for _, c := range name {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	case "openid.net":
		return u.Path == "/specs/openid-connect-core-1_0-errata2.html" || u.Path == "/specs/openid-connect-discovery-1_0-errata2.html"
	case "raw.githubusercontent.com":
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		return len(parts) > 4 && parts[0] == "modelcontextprotocol" && (parts[1] == "modelcontextprotocol" || parts[1] == "ext-auth") && commitPin.MatchString(parts[2])
	}
	return false
}
