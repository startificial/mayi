package web

import (
	"strings"
	"testing"
)

func TestConnectedAppsEscapesMetadataAndUsesExplicitRevokeTarget(t *testing.T) {
	body, err := ConnectedAppsPage(ConnectedApps{Grants: []ConnectedGrant{{Client: "<script>bad()</script>", Resource: "https://api.example", RevokeAction: "/t/a/grants/example/revoke", LastUsed: "2026-10-18T12:00:00Z", TokensIssued: 2}}})
	if err != nil || strings.Contains(string(body), "<script>") || !strings.Contains(string(body), `action="/t/a/grants/example/revoke"`) || !strings.Contains(string(body), "Last token use/check") {
		t.Fatal("unsafe or incomplete connected view", err)
	}
}
