package clients

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
)

const MaxClientIDBytes = 2048

var ErrMetadataDenied = errors.New("client metadata denied")
var ErrMetadataUnavailable = errors.New("client metadata unavailable")

// MetadataHost is a canonical ASCII DNS host, without ports or wildcards. Host
// admission is exact; a parent domain never implicitly approves subdomains.
func ValidMetadataHost(host string) bool {
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	letter := false
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' {
				letter = true
			} else if !(c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return letter
}

// MetadataURL preserves exact identity bytes. This public profile uses DNS,
// HTTPS/default port, a path and no query; literal IPs and dot paths are refused.
func MetadataURL(raw string) (*url.URL, bool) {
	if len(raw) > MaxClientIDBytes || strings.ContainsAny(raw, "\\?#") {
		return nil, false
	}
	for _, c := range raw {
		if c <= 0x20 || c >= 0x7f {
			return nil, false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Path == "" || !ValidMetadataHost(u.Hostname()) || u.Host != strings.ToLower(u.Host) || (u.Host != u.Hostname() && u.Host != u.Hostname()+":443") || u.Port() != "" && u.Port() != "443" || u.String() != raw || strings.Contains(u.Path, "\\") {
		return nil, false
	}
	for _, c := range u.Path {
		if c <= 0x20 || c == 0x7f {
			return nil, false
		}
	}
	for _, p := range strings.Split(u.Path, "/") {
		if p == "." || p == ".." {
			return nil, false
		}
	}
	return u, true
}

func ValidMetadataDigest(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
}

// Accepted revisions are monotonic even if a publisher later restores an old
// document. Reverting metadata must never resurrect an earlier credential.
func RevisionedMetadataDigest(content string, revision uint64) (string, bool) {
	if !ValidMetadataDigest(content) || revision == 0 || revision > 1<<63-1 {
		return "", false
	}
	b, err := json.Marshal(struct {
		Content  string
		Revision uint64
	}{content, revision})
	if err != nil {
		return "", false
	}
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:]), true
}

type RedirectApproval struct {
	ClientID     string
	RedirectURIs []string
}

// MetadataPolicy is the client registry's CIMD admission policy. It controls
// future decisions as well as existing CIMD authority through its version.
type MetadataPolicy struct {
	Version                                                      uint64
	Mode                                                         string
	Hosts, ApprovedClients, Resources, AuthorizationDetailsTypes []string
	RedirectApprovals                                            []RedirectApproval
	MaxClients, AccessTokenSeconds                               int
}

func DefaultMetadataPolicy() MetadataPolicy { return MetadataPolicy{Version: 1, Mode: "admin_only"} }

// Explicit restrictive admission cannot be bypassed by public DCR. The
// unconfigured default preserves DCR's separate administrator-controlled opt-in.
func (p MetadataPolicy) AllowsDynamicRegistration() bool {
	return p.Valid() && (p.Version == 1 && !p.Enabled() || p.Mode == "any")
}
func (p MetadataPolicy) Enabled() bool {
	return p.Mode == "any" || p.Mode == "hosts" || len(p.ApprovedClients) > 0
}
func (p MetadataPolicy) Valid() bool {
	if p.Version == 0 || p.Version > 1<<63-1 || p.Mode != "any" && p.Mode != "hosts" && p.Mode != "admin_only" || len(p.Hosts) > 64 || len(p.ApprovedClients) > 64 || len(p.RedirectApprovals) > 64 {
		return false
	}
	if p.Mode == "hosts" && len(p.Hosts) == 0 || p.Mode != "hosts" && len(p.Hosts) > 0 {
		return false
	}
	seen := map[string]bool{}
	for _, host := range p.Hosts {
		if !ValidMetadataHost(host) || seen[host] {
			return false
		}
		seen[host] = true
	}
	seen = map[string]bool{}
	for _, id := range p.ApprovedClients {
		if _, ok := MetadataURL(id); !ok || seen[id] {
			return false
		}
		seen[id] = true
	}
	seen = map[string]bool{}
	for _, a := range p.RedirectApprovals {
		if _, ok := MetadataURL(a.ClientID); !ok || seen[a.ClientID] || len(a.RedirectURIs) == 0 || len(a.RedirectURIs) > 16 {
			return false
		}
		seen[a.ClientID] = true
		redirects := map[string]bool{}
		for _, r := range a.RedirectURIs {
			if !ValidApplicationRedirect("native", r) || redirects[r] {
				return false
			}
			redirects[r] = true
		}
	}
	if !p.Enabled() {
		return len(p.Resources) == 0 && len(p.AuthorizationDetailsTypes) == 0 && len(p.RedirectApprovals) == 0 && p.MaxClients == 0 && p.AccessTokenSeconds == 0
	}
	return (RegistrationPolicy{Version: 1, Mode: "open", Resources: p.Resources, AuthorizationDetailsTypes: p.AuthorizationDetailsTypes, MaxClients: p.MaxClients, AccessTokenSeconds: p.AccessTokenSeconds}).Valid()
}

func (p MetadataPolicy) Allows(id string) bool {
	u, ok := MetadataURL(id)
	if !ok || !p.Valid() {
		return false
	}
	switch p.Mode {
	case "any":
		return true
	case "hosts":
		return slices.Contains(p.Hosts, u.Hostname())
	case "admin_only":
		return slices.Contains(p.ApprovedClients, id)
	}
	return false
}

type MetadataDocument struct {
	ClientID, Name, ApplicationType         string
	RedirectURIs, AuthorizationDetailsTypes []string
}

func (p MetadataPolicy) Client(d MetadataDocument) (Client, bool) {
	if !p.Allows(d.ClientID) {
		return Client{}, false
	}
	u, _ := MetadataURL(d.ClientID)
	name := d.Name
	if name == "" {
		name = u.Hostname()
	}
	types := d.AuthorizationDetailsTypes
	if len(types) == 0 {
		types = p.AuthorizationDetailsTypes
	}
	c, ok := (RegistrationPolicy{Version: 1, Mode: "open", Resources: p.Resources, AuthorizationDetailsTypes: p.AuthorizationDetailsTypes, MaxClients: p.MaxClients, AccessTokenSeconds: p.AccessTokenSeconds}).Client("metadata", PublicRegistration{Name: name, ApplicationType: d.ApplicationType, RedirectURIs: d.RedirectURIs, Resources: p.Resources, AuthorizationDetailsTypes: types})
	if !ok {
		return Client{}, false
	}
	for _, r := range c.RedirectURIs {
		v, err := url.Parse(r)
		same := err == nil && v.Scheme == "https" && v.Hostname() == u.Hostname() && (v.Port() == "" || v.Port() == "443")
		if same && c.EffectiveApplicationType() == "web" {
			continue
		}
		approved := false
		for _, a := range p.RedirectApprovals {
			if a.ClientID == d.ClientID && slices.Contains(a.RedirectURIs, r) {
				approved = true
			}
		}
		if !approved {
			return Client{}, false
		}
	}
	c.ID = d.ClientID
	c.MetadataPolicyVersion = p.Version
	// Fixed-field JSON is only a canonical fingerprint preimage, never a wire
	// contract or stored driver model. Unknown metadata cannot change authority.
	b, err := json.Marshal(struct {
		Version                     uint64
		ID, Name, Application       string
		Redirects, Resources, Types []string
		Seconds                     int
	}{p.Version, c.ID, c.Name, c.EffectiveApplicationType(), c.RedirectURIs, c.Resources, c.AuthorizationDetailsTypes, c.AccessTokenSeconds})
	if err != nil {
		return Client{}, false
	}
	digest := sha256.Sum256(b)
	c.MetadataDigest = hex.EncodeToString(digest[:])
	return c, c.Valid()
}
