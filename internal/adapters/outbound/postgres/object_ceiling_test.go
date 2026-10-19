package postgres

import (
	"bytes"
	"strings"
	"testing"

	"github.com/startificial/mayi/internal/domain/grants"
)

func TestObjectCeilingRecordRehydratesStrictly(t *testing.T) {
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	resource := "https://api.example"
	ceiling, err := grants.NewObjectCeiling(grants.ObjectCeilingSpec{Scope: scope, Resource: resource, Details: []grants.ObjectDetail{{Type: "https://api.example/types/file/v1", Identifier: "file:123", Actions: []string{"download"}}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeObjectCeiling(ceiling, scope, resource)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeObjectCeiling(raw, scope, resource)
	if err != nil || !back.Equal(ceiling) {
		t.Fatal("stored object authority changed", err)
	}
	for name, data := range map[string][]byte{
		"empty bytes": {}, "json null": []byte("null"), "array": []byte("[]"),
		"version":       bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1),
		"semantics":     bytes.Replace(raw, []byte(`object-actions-v1`), []byte(`object-actions-v2`), 1),
		"audience":      bytes.ReplaceAll(raw, []byte(resource), []byte("https://other.example")),
		"field case":    bytes.Replace(raw, []byte(`"identifier"`), []byte(`"Identifier"`), 1),
		"unknown field": bytes.Replace(raw, []byte(`"identifier"`), []byte(`"extra":"untrusted","identifier"`), 1),
		"empty actions": bytes.Replace(raw, []byte(`["download"]`), []byte(`[]`), 1),
		"null action":   bytes.Replace(raw, []byte(`["download"]`), []byte(`[null]`), 1),
		"wildcard":      bytes.Replace(raw, []byte(`file:123`), []byte(`*`), 1),
		"empty details": []byte(`{"version":1,"semantics":"object-actions-v1","resource":"https://api.example","details":[]}`),
		"oversized":     []byte(strings.Repeat(" ", maxObjectCeilingRecordBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if c, err := decodeObjectCeiling(data, scope, resource); err == nil || !c.IsZero() {
				t.Fatal("invalid record rehydrated authority", err)
			}
		})
	}
	missing, err := decodeObjectCeiling(nil, scope, resource)
	if err != nil || !missing.IsZero() || missing.Equal(ceiling) {
		t.Fatal("SQL NULL acquired object authority", err)
	}

	if _, err := encodeObjectCeiling(ceiling, grants.Scope{TenantID: "b", Issuer: scope.Issuer}, resource); err == nil {
		t.Fatal("foreign tenant encoded")
	}
}
