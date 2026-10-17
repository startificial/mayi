package resources

import "testing"

func TestURIRejectsAmbiguousOrUnboundedTargets(t *testing.T) {
	for _, uri := range []string{"https://", "http://api.example", "https://user:secret@api.example", "https://api.example?x=y", "https://api.example#x", "https://api.example:0", "https://api.example:65536", "https://api.example:0443", "https://API.example", "https://api.example.", "https://api.example\\evil", "https://api.example\x01"} {
		if ValidURI(uri) {
			t.Fatalf("accepted %q", uri)
		}
	}
	for _, uri := range []string{"https://api.example", "https://api.example/v1", "https://api.example:8443/a%20b"} {
		if !ValidURI(uri) {
			t.Fatalf("rejected %q", uri)
		}
	}
}
