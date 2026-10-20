package web

import (
	"strings"
	"testing"
)

func TestConsentObjectDisplayEscapesNamesAndPreservesExactReferences(t *testing.T) {
	view := Consent{ClientID: "web", ResourceURI: "https://api.example", Objects: []ConsentObject{{Type: "https://api.example/types/workflow/v1", Identifier: "workflow:123", Name: `<script>private()</script>`, Actions: []Permission{{Name: "read", Description: `<img src=x onerror=private()>`}}}}}
	page, err := ConsentPage(view)
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, want := range []string{"workflow:123", "https://api.example/types/workflow/v1", "&lt;script&gt;private()&lt;/script&gt;", "&lt;img src=x onerror=private()&gt;", "Approval is currently unavailable.", "Registration does not verify the publisher."} {
		if !strings.Contains(html, want) {
			t.Fatal("missing safe exact display", want)
		}
	}
	for _, forbidden := range []string{"<script>", "<img ", `value="approve"`, `value="deny"`, "workflow:124"} {
		if strings.Contains(html, forbidden) {
			t.Fatal("unsafe or unsupported display", forbidden)
		}
	}
	view.DecisionAvailable = true
	page, err = ConsentPage(view)
	if err != nil || !strings.Contains(string(page), `value="approve"`) || !strings.Contains(string(page), `value="deny"`) {
		t.Fatal("supported consent lost decisions", err)
	}
}
