package postgres

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/administration"
)

func (m *management) RegisterObjectProfile(ctx context.Context, resourceID string, profile resources.ObjectProfile) error {
	s := profile.Snapshot()
	if _, err := resources.NewObjectProfile(s); err != nil || s.Scope != m.scope || !resources.ValidID(resourceID) {
		return administration.ErrInvalid
	}
	// A JSON object keeps each registered action attached to its description.
	// Domain validation rejects duplicates before persistence; JSONB is the
	// internal record format, not arbitrary client-supplied authorization JSON.
	actions := make(map[string]string, len(s.Actions))
	for _, action := range s.Actions {
		actions[action.Name] = action.Description
	}
	data, err := json.Marshal(actions)
	if err != nil {
		return administration.ErrInvalid
	}
	_, err = m.tx.Exec(ctx, `INSERT INTO mayi.resource_object_profiles(tenant_id,resource_id,resource_uri,type_uri,semantics,actions) VALUES($1,$2,$3,$4,$5,$6)`, m.scope.TenantID, resourceID, s.Resource, s.Type, s.Semantics, data)
	return classifyManagement(err)
}

func (m *management) ObjectProfile(ctx context.Context, resourceID, typeURI string) (resources.ObjectProfile, error) {
	s := resources.ObjectProfileSpec{Scope: m.scope, Type: typeURI}
	var data []byte
	err := m.tx.QueryRow(ctx, `SELECT resource_uri,semantics,actions FROM mayi.resource_object_profiles WHERE tenant_id=$1 AND resource_id=$2 AND type_uri=$3`, m.scope.TenantID, resourceID, typeURI).Scan(&s.Resource, &s.Semantics, &data)
	if err != nil {
		return resources.ObjectProfile{}, classifyManagement(err)
	}
	return rehydrateObjectProfile(s, data)
}

func (m *management) ClientObjectProfile(ctx context.Context, typeURI string, resourceIDs []string) (resources.ObjectProfile, error) {
	if !resources.ValidObjectTypeURI(typeURI) || len(resourceIDs) == 0 || len(resourceIDs) > 32 {
		return resources.ObjectProfile{}, administration.ErrInvalid
	}
	for _, id := range resourceIDs {
		if !resources.ValidID(id) {
			return resources.ObjectProfile{}, administration.ErrInvalid
		}
	}
	s := resources.ObjectProfileSpec{Scope: m.scope, Type: typeURI}
	var data []byte
	err := m.tx.QueryRow(ctx, `SELECT resource_uri,semantics,actions FROM mayi.resource_object_profiles WHERE tenant_id=$1 AND type_uri=$2 AND resource_id=ANY($3)`, m.scope.TenantID, typeURI, resourceIDs).Scan(&s.Resource, &s.Semantics, &data)
	if err != nil {
		return resources.ObjectProfile{}, classifyManagement(err)
	}
	return rehydrateObjectProfile(s, data)
}

func rehydrateObjectProfile(s resources.ObjectProfileSpec, data []byte) (resources.ObjectProfile, error) {
	var actions map[string]string
	if err := json.Unmarshal(data, &actions); err != nil {
		return resources.ObjectProfile{}, administration.ErrUnavailable
	}
	var names []string
	for name := range actions {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		s.Actions = append(s.Actions, resources.ObjectAction{Name: name, Description: actions[name]})
	}
	profile, err := resources.NewObjectProfile(s)
	if err != nil {
		return resources.ObjectProfile{}, administration.ErrUnavailable
	}
	return profile, nil
}
