package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// External test services have a separate source/build boundary from Mayi's Go
// module. Evidence covers their linked code, not unexecuted upstream test suites.
type serviceArtifact struct {
	Name     string         `json:"name"`
	Version  string         `json:"version"`
	Licenses []string       `json:"licenses"`
	Source   string         `json:"source"`
	SHA256   string         `json:"sha256"`
	Review   string         `json:"review"`
	Files    []evidenceFile `json:"files"`
}
type serviceInventory struct {
	Version   int               `json:"version"`
	Artifacts []serviceArtifact `json:"artifacts"`
}

func checkServices(root string) error {
	var policy licensePolicy
	if err := readJSON(filepath.Join(root, "tools/license-policy.json"), &policy); err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, label := range policy.Allowed {
		allowed[label] = true
	}
	var inventory serviceInventory
	if err := readJSON(filepath.Join(root, "tools/services.json"), &inventory); err != nil {
		return err
	}
	if inventory.Version != 1 || len(inventory.Artifacts) != 2 {
		return fmt.Errorf("expected two reviewed P0 service artifacts")
	}
	seen := map[string]bool{}
	for _, a := range inventory.Artifacts {
		if seen[a.Name] || !slices.Contains([]string{"postgresql", "openbao"}, a.Name) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(a.SHA256) {
			return fmt.Errorf("invalid service artifact %s", a.Name)
		}
		seen[a.Name] = true
		// MPL's Go proxy source-access rule applies to Go modules. This artifact
		// instead retains an exact upstream source tarball and component sources.
		labels := slices.Clone(a.Licenses)
		if slices.Contains(labels, "MPL-2.0") && (!allowed["MPL-2.0"] || !strings.Contains(a.Source, "a5db72cef75c24b920ade02065b18dd8eb666bac")) {
			return fmt.Errorf("unreviewed MPL service source")
		}
		labels = slices.DeleteFunc(labels, func(s string) bool { return s == "MPL-2.0" })
		if err := validateEvidence(dependency{Name: a.Name, Version: a.Version, Licenses: labels, Source: a.Source, Review: a.Review, Files: a.Files}, allowed, root); err != nil {
			return err
		}
		if a.Name == "openbao" {
			var components []struct {
				Name, Version, Source, Review string
				Licenses                      []string
			}
			if err := readJSON(filepath.Join(root, "docs/p0/openbao-components.json"), &components); err != nil {
				return err
			}
			if len(components) == 0 {
				return fmt.Errorf("missing OpenBao component inventory")
			}
			union := map[string]bool{}
			identities := map[string]bool{}
			for _, component := range components {
				key := component.Name + "@" + component.Version
				if identities[key] || component.Name == "" || component.Version == "" || !strings.HasPrefix(component.Source, "https://") || component.Review == "" || len(component.Licenses) == 0 {
					return fmt.Errorf("invalid service component %s", key)
				}
				identities[key] = true
				for _, label := range component.Licenses {
					if !allowed[label] {
						return fmt.Errorf("%s: disallowed service license %s", key, label)
					}
					union[label] = true
				}
			}
			if len(union) != len(a.Licenses) {
				return fmt.Errorf("service license union differs from reviewed components")
			}
			for _, label := range a.Licenses {
				if !union[label] {
					return fmt.Errorf("service license union differs from reviewed components")
				}
			}
		}
	}
	return nil
}
