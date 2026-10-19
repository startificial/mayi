package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

func rarProfile(t testing.TB) resources.DocumentProfile {
	t.Helper()
	p, err := resources.NewDocumentProfile(resources.DocumentProfileSpec{
		Scope: grants.Scope{TenantID: "tenant-a", Issuer: "https://auth.example/t/a"}, Resource: "https://api.example/documents", Type: "https://api.example/types/document/v1", Semantics: resources.DocumentV1,
		Actions: []resources.DocumentAction{{Name: "read", Description: "Read document"}, {Name: "write", Description: "Change document"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func rarEntry(identifier, action string) string {
	// Only test-controlled ASCII literals are interpolated here.
	return fmt.Sprintf(`{"type":"https://api.example/types/document/v1","locations":["https://api.example/documents"],"identifier":"%s","actions":["%s"]}`, identifier, action)
}
func rarRequest() string { return "[" + rarEntry("123", "read") + "," + rarEntry("124", "write") + "]" }

func TestAuthorizationDetailsStandardEnvelopeRoundTrip(t *testing.T) {
	p := rarProfile(t)
	c, err := DecodeAuthorizationDetails(rarRequest(), p)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Snapshot()
	if !c.Permits(s.Scope, s.Resource, s.Type, "123", "read") || c.Permits(s.Scope, s.Resource, s.Type, "123", "write") || c.Permits(s.Scope, s.Resource, s.Type, "124", "read") {
		t.Fatal("wire mapping recombined object/action tuples")
	}
	raw, err := EncodeAuthorizationDetails(c, p)
	if err != nil {
		t.Fatal(err)
	}
	var wire []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil || len(wire) != 2 {
		t.Fatalf("invalid standard envelope: %v", err)
	}
	for _, entry := range wire {
		if len(entry) != 4 || entry["type"] == nil || entry["locations"] == nil || entry["identifier"] == nil || entry["actions"] == nil {
			t.Fatal("nonstandard profile fields emitted")
		}
	}
	back, err := DecodeAuthorizationDetails(string(raw), p)
	if err != nil || !back.IsSubsetOf(c) || !c.IsSubsetOf(back) {
		t.Fatalf("round trip changed authority: %v", err)
	}
	// JSON escaping is decoded once; opaque identifiers are not URL-decoded.
	escaped := strings.Replace("["+rarEntry("123%2Fchild", "read")+"]", `"identifier"`, `"\u0069dentifier"`, 1)
	encoded, err := DecodeAuthorizationDetails(escaped, p)
	if err != nil || !encoded.Permits(s.Scope, s.Resource, s.Type, "123%2Fchild", "read") || encoded.Permits(s.Scope, s.Resource, s.Type, "123/child", "read") {
		t.Fatalf("opaque object identifier normalized: %v", err)
	}
}

func TestAuthorizationDetailsRejectsAmbiguousOrUnsupportedInput(t *testing.T) {
	valid := "[" + rarEntry("123", "read") + "]"
	replace := func(old, next string) string { return strings.Replace(valid, old, next, 1) }
	cases := map[string]string{
		"missing": "", "null": "null", "object": rarEntry("123", "read"), "empty": "[]", "null entry": "[null]",
		"trailing value": valid + ` []`, "trailing garbage": valid + `x`, "trailing comma": strings.TrimSuffix(valid, "]") + ",]",
		"duplicate field":          replace(`"identifier":"123"`, `"identifier":"123","identifier":"124"`),
		"escaped duplicate field":  replace(`"identifier":"123"`, `"identifier":"123","\u0069dentifier":"124"`),
		"case folded field":        replace(`"identifier"`, `"Identifier"`),
		"unknown field":            replace(`"identifier":"123"`, `"identifier":"123","title":"client-controlled secret"`),
		"unsupported data field":   replace(`"identifier":"123"`, `"identifier":"123","datatypes":["content"]`),
		"missing identifier":       replace(`"identifier":"123",`, ""),
		"missing type":             replace(`"type":"https://api.example/types/document/v1",`, ""),
		"missing locations":        replace(`"locations":["https://api.example/documents"],`, ""),
		"missing actions":          replace(`,"actions":["read"]`, ""),
		"empty identifier":         replace(`"identifier":"123"`, `"identifier":""`),
		"wildcard identifier":      replace(`"identifier":"123"`, `"identifier":"*"`),
		"identifier number":        replace(`"identifier":"123"`, `"identifier":123`),
		"identifier null":          replace(`"identifier":"123"`, `"identifier":null`),
		"identifier array":         replace(`"identifier":"123"`, `"identifier":["123"]`),
		"identifier control":       replace(`"identifier":"123"`, `"identifier":"123\u0000"`),
		"unpaired high surrogate":  replace(`"identifier":"123"`, `"identifier":"123\ud800"`),
		"unpaired low surrogate":   replace(`"identifier":"123"`, `"identifier":"123\udfff"`),
		"empty actions":            replace(`["read"]`, `[]`),
		"action string":            replace(`["read"]`, `"read"`),
		"action null":              replace(`["read"]`, `[null]`),
		"action object":            replace(`["read"]`, `[{"action":"read"}]`),
		"duplicate action":         replace(`["read"]`, `["read","read"]`),
		"wildcard action":          replace(`["read"]`, `["*"]`),
		"unknown action":           replace(`["read"]`, `["admin"]`),
		"unknown type":             replace(`/types/document/v1`, `/types/document/v2`),
		"type null":                replace(`"https://api.example/types/document/v1"`, `null`),
		"empty locations":          replace(`["https://api.example/documents"]`, `[]`),
		"locations null":           replace(`["https://api.example/documents"]`, `null`),
		"locations string":         replace(`["https://api.example/documents"]`, `"https://api.example/documents"`),
		"multiple locations":       replace(`["https://api.example/documents"]`, `["https://api.example/documents","https://api.example/other"]`),
		"duplicate location":       replace(`["https://api.example/documents"]`, `["https://api.example/documents","https://api.example/documents"]`),
		"foreign audience":         replace(`"https://api.example/documents"`, `"https://other.example/documents"`),
		"audience prefix":          replace(`"https://api.example/documents"`, `"https://api.example/documents/123"`),
		"audience normalization":   replace(`"https://api.example/documents"`, `"https://api.example:443/documents"`),
		"deep nested extension":    replace(`"identifier":"123"`, `"identifier":"123","extra":`+strings.Repeat("[", 1000)+`0`+strings.Repeat("]", 1000)),
		"deep nested known member": replace(`"identifier":"123"`, `"identifier":`+strings.Repeat("[", 1000)+`"123"`+strings.Repeat("]", 1000)),
		"duplicate object":         "[" + rarEntry("123", "read") + "," + rarEntry("123", "read") + "]",
		"split same object":        "[" + rarEntry("123", "read") + "," + rarEntry("123", "write") + "]",
		"invalid utf8":             replace(`123`, string([]byte{0xff})),
		"oversized":                valid + strings.Repeat(" ", MaxAuthorizationDetailsBytes),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := DecodeAuthorizationDetails(raw, rarProfile(t))
			if !errors.Is(err, ErrInvalidAuthorizationDetails) || len(c.Snapshot().Details) != 0 {
				t.Fatalf("invalid request produced authority: %v", err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "123") {
				t.Fatal("error disclosed request values")
			}
		})
	}
}

func TestAuthorizationDetailsBoundsAndInvalidEncoding(t *testing.T) {
	p := rarProfile(t)
	var entries []string
	for i := 0; i < grants.MaxObjectDetails; i++ {
		entries = append(entries, rarEntry(fmt.Sprint(i), "read"))
	}
	valid := "[" + strings.Join(entries, ",") + "]"
	if _, err := DecodeAuthorizationDetails(valid, p); err != nil {
		t.Fatal("maximum entry count rejected", err)
	}
	tooMany := "[" + strings.Join(append(entries, rarEntry("extra", "read")), ",") + "]"
	if _, err := DecodeAuthorizationDetails(tooMany, p); err == nil {
		t.Fatal("excess entry count accepted")
	}
	for _, count := range []int{MaxAuthorizationDetailsBytes, MaxAuthorizationDetailsBytes + 1} {
		raw := valid + strings.Repeat(" ", count-len(valid))
		_, err := DecodeAuthorizationDetails(raw, p)
		if (err == nil) != (count == MaxAuthorizationDetailsBytes) {
			t.Fatalf("incorrect byte bound at %d: %v", count, err)
		}
	}
	// A compact request must also fit after standard JSON escaping on output.
	var expansion []string
	for i := 0; i < grants.MaxObjectDetails; i++ {
		expansion = append(expansion, rarEntry(strings.Repeat("<", 250)+fmt.Sprint(i), "read"))
	}
	if _, err := DecodeAuthorizationDetails("["+strings.Join(expansion, ",")+"]", p); err == nil {
		t.Fatal("accepted details whose escaped response exceeds the bound")
	}
	for _, count := range []int{grants.MaxObjectIdentifierBytes, grants.MaxObjectIdentifierBytes + 1} {
		_, err := DecodeAuthorizationDetails("["+rarEntry(strings.Repeat("x", count), "read")+"]", p)
		if (err == nil) != (count == grants.MaxObjectIdentifierBytes) {
			t.Fatalf("incorrect identifier bound at %d: %v", count, err)
		}
	}
	if _, err := DecodeAuthorizationDetails(valid, resources.DocumentProfile{}); err == nil {
		t.Fatal("unregistered profile decoded")
	}
	if _, err := EncodeAuthorizationDetails(grants.ObjectCeiling{}, p); err == nil {
		t.Fatal("missing ceiling serialized")
	}
	bound := p.Snapshot()
	empty, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: bound.Scope, Resource: bound.Resource})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeAuthorizationDetails(empty, p); err == nil {
		t.Fatal("empty authority emitted as assigned document permissions")
	}
	for name, mutate := range map[string]func(*grants.ObjectCeilingSpec){
		"foreign tenant":   func(s *grants.ObjectCeilingSpec) { s.Scope.TenantID = "tenant-b" },
		"foreign issuer":   func(s *grants.ObjectCeilingSpec) { s.Scope.Issuer += "/other" },
		"foreign resource": func(s *grants.ObjectCeilingSpec) { s.Resource += "/other" },
		"unknown type":     func(s *grants.ObjectCeilingSpec) { s.Details[0].Type += "/other" },
		"unknown action":   func(s *grants.ObjectCeilingSpec) { s.Details[0].Actions = []string{"admin"} },
	} {
		t.Run(name, func(t *testing.T) {
			c, err := DecodeAuthorizationDetails(rarRequest(), p)
			if err != nil {
				t.Fatal(err)
			}
			s := c.Snapshot()
			mutate(&s)
			foreign, err := grants.NewObjectCeiling(s)
			if err != nil {
				t.Fatal(err)
			}
			if data, err := EncodeAuthorizationDetails(foreign, p); err == nil || len(data) != 0 {
				t.Fatal("unregistered permissions disclosed")
			}
		})
	}
}

func FuzzAuthorizationDetails(f *testing.F) {
	p := rarProfile(f)
	for _, seed := range []string{rarRequest(), "[]", "null", `[{}]`, `[{"identifier":"123","identifier":"124"}]`, "[" + rarEntry(`123\ud800`, "read") + "]"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		c, err := DecodeAuthorizationDetails(raw, p)
		if err != nil {
			if !errors.Is(err, ErrInvalidAuthorizationDetails) {
				t.Fatal("unclassified parse error")
			}
			return
		}
		encoded, err := EncodeAuthorizationDetails(c, p)
		if err != nil {
			t.Fatal("accepted details cannot be encoded", err)
		}
		back, err := DecodeAuthorizationDetails(string(encoded), p)
		if err != nil || !back.IsSubsetOf(c) || !c.IsSubsetOf(back) {
			t.Fatal("round trip changed object authority")
		}
	})
}
