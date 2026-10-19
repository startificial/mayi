package postgres

import (
	"encoding/json"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

// This is a versioned persistence record, not the RFC 9396 wire envelope.
// Tenant/issuer identity comes from the scoped row and immutable tenant record.
type objectCeilingRecord struct {
	Version   int                  `json:"version"`
	Semantics string               `json:"semantics"`
	Resource  string               `json:"resource"`
	Details   []objectDetailRecord `json:"details"`
}
type objectDetailRecord struct {
	Type       string   `json:"type"`
	Identifier string   `json:"identifier"`
	Actions    []string `json:"actions"`
}

const maxObjectCeilingRecordBytes = 1 << 20

func encodeObjectCeiling(c grants.ObjectCeiling, scope grants.Scope, resource string) ([]byte, error) {
	if c.IsZero() {
		return nil, grants.ErrInvalidObjectCeiling
	}
	s := c.Snapshot()
	if !c.BoundTo(scope, resource) || len(s.Details) == 0 {
		return nil, grants.ErrInvalidObjectCeiling
	}
	record := objectCeilingRecord{Version: 1, Semantics: resources.ObjectActionsV1, Resource: s.Resource}
	for _, d := range s.Details {
		record.Details = append(record.Details, objectDetailRecord{Type: d.Type, Identifier: d.Identifier, Actions: d.Actions})
	}
	data, err := json.Marshal(record)
	if err != nil || len(data) > maxObjectCeilingRecordBytes {
		return nil, grants.ErrInvalidObjectCeiling
	}
	return data, nil
}

// JSONB has unique decoded member names. Check exact names at each record level
// rather than using encoding/json's case-insensitive struct matching. Domain
// constructors remain the authoritative semantic validators on rehydration.
func recordMembers(data []byte, names ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != len(names) {
		return nil, grants.ErrInvalidObjectCeiling
	}
	for _, name := range names {
		if len(fields[name]) == 0 || string(fields[name]) == "null" {
			return nil, grants.ErrInvalidObjectCeiling
		}
	}
	return fields, nil
}

func decodeObjectCeiling(data []byte, scope grants.Scope, resource string) (grants.ObjectCeiling, error) {
	if data == nil {
		return grants.ObjectCeiling{}, grants.ErrInvalidObjectCeiling
	}
	if len(data) == 0 || len(data) > maxObjectCeilingRecordBytes {
		return grants.ObjectCeiling{}, grants.ErrInvalidObjectCeiling
	}
	fields, err := recordMembers(data, "version", "semantics", "resource", "details")
	if err != nil {
		return grants.ObjectCeiling{}, err
	}
	var version int
	var semantics, audience string
	var entries []json.RawMessage
	if json.Unmarshal(fields["version"], &version) != nil || version != 1 || json.Unmarshal(fields["semantics"], &semantics) != nil || semantics != resources.ObjectActionsV1 || json.Unmarshal(fields["resource"], &audience) != nil || audience != resource || json.Unmarshal(fields["details"], &entries) != nil || len(entries) == 0 || len(entries) > grants.MaxObjectDetails {
		return grants.ObjectCeiling{}, grants.ErrInvalidObjectCeiling
	}
	s := grants.ObjectCeilingSpec{Scope: scope, Resource: audience}
	for _, entry := range entries {
		members, err := recordMembers(entry, "type", "identifier", "actions")
		if err != nil {
			return grants.ObjectCeiling{}, err
		}
		var detail grants.ObjectDetail
		if json.Unmarshal(members["type"], &detail.Type) != nil || json.Unmarshal(members["identifier"], &detail.Identifier) != nil || json.Unmarshal(members["actions"], &detail.Actions) != nil {
			return grants.ObjectCeiling{}, grants.ErrInvalidObjectCeiling
		}
		s.Details = append(s.Details, detail)
	}
	return grants.NewObjectCeiling(s)
}
