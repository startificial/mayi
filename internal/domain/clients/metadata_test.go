package clients

import (
	"strings"
	"testing"
)

func metadataPolicy() MetadataPolicy {
	return MetadataPolicy{Version: 2, Mode: "hosts", Hosts: []string{"agent.example"}, Resources: []string{"api"}, AuthorizationDetailsTypes: []string{"https://api.example/types/item"}, MaxClients: 10, AccessTokenSeconds: 120}
}
func TestCIMDIdentityAndHostAdmissionAreExact(t *testing.T) {
	p := metadataPolicy()
	id := "https://agent.example/client.json"
	if !p.Valid() || !p.Allows(id) {
		t.Fatal("valid host not admitted")
	}
	for _, bad := range []string{"http://agent.example/client.json", "https://agent.example", "https://user@agent.example/c", "https://agent.example/c?x=1", "https://agent.example/c#x", "https://agent.example:8443/c", "https://agent.example/a/../c", "https://agent.example/%2e%2e/c", "https://127.0.0.1/c", "https://[::ffff:8.8.8.8]/c", "https://AGENT.example/c", "https://agent.example./c", id + strings.Repeat("x", 2048)} {
		if ValidClientID(bad) {
			t.Fatal("invalid identity admitted", bad)
		}
	}
	for _, bad := range []string{"https://agent.example.evil/c", "https://child.agent.example/c", "https://other.example/c"} {
		if p.Allows(bad) {
			t.Fatal("host boundary widened")
		}
	}
	p.Mode = "admin_only"
	p.Hosts = nil
	p.ApprovedClients = []string{id}
	if !p.Allows(id) || p.Allows(id+"/other") || p.Allows("https://agent.example:443/client.json") {
		t.Fatal("administrator approval is not exact")
	}
	p.Mode = "any"
	p.ApprovedClients = nil
	if !p.Allows("https://other.example/client.json") {
		t.Fatal("any-client mode failed")
	}
	if DefaultMetadataPolicy().Allows(id) {
		t.Fatal("default admission open")
	}
}
func TestCIMDRedirectExceptionsAndDigestPreserveAuthority(t *testing.T) {
	p := metadataPolicy()
	d := MetadataDocument{ClientID: "https://agent.example/client.json", Name: "Agent", RedirectURIs: []string{"https://agent.example/callback"}}
	c, ok := p.Client(d)
	if !ok || !c.Valid() || !c.RequireBinding || c.AuthMethod != "none" || c.Machine || c.Introspection || !ValidMetadataDigest(c.MetadataDigest) {
		t.Fatal("unsafe CIMD client")
	}
	d.Name = "Changed agent"
	changed, ok := p.Client(d)
	if !ok || changed.MetadataDigest == c.MetadataDigest {
		t.Fatal("display change did not pin new metadata")
	}
	d.RedirectURIs = []string{"https://other.example/callback"}
	if _, ok := p.Client(d); ok {
		t.Fatal("unapproved cross-origin redirect")
	}
	p.RedirectApprovals = []RedirectApproval{{ClientID: d.ClientID, RedirectURIs: []string{"https://other.example/callback"}}}
	if _, ok := p.Client(d); !ok {
		t.Fatal("exact reviewed exception rejected")
	}
	d.RedirectURIs = []string{"https://other.example/other"}
	if _, ok := p.Client(d); ok {
		t.Fatal("exception allowed a different path")
	}
	d.ApplicationType = "native"
	d.RedirectURIs = []string{"http://127.0.0.1/cb"}
	if _, ok := p.Client(d); ok {
		t.Fatal("native exception was implicit")
	}
	p.RedirectApprovals[0].RedirectURIs = d.RedirectURIs
	native, ok := p.Client(d)
	if !ok || !native.AllowsRedirect("http://127.0.0.1:45678/cb") {
		t.Fatal("reviewed native loopback policy lost")
	}
	p.Version++
	next, ok := p.Client(d)
	if !ok || next.MetadataDigest == native.MetadataDigest {
		t.Fatal("host-policy revision did not change correlation")
	}
}
