package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/services/authorization"
)

type consentLabelRecord struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
}

func (a *authorizationTransaction) presentationAllowed(w domain.Transaction, p domain.ObjectConsentProjection, now time.Time) bool {
	s := w.Snapshot()
	return a.principal != nil && a.consentHash == s.HandleHash && s.Request.TenantIssuer == a.tenantIssuer && s.ConsentSessionHash == a.principal.SessionHash && s.PolicyVersion == a.version && p.Matches(w, a.principal.Subject) && !now.Before(s.CreatedAt) && now.Before(s.ExpiresAt)
}

func (a *authorizationTransaction) RecordObjectPresentation(ctx context.Context, w domain.Transaction, p domain.ObjectConsentProjection, now time.Time) error {
	if !a.presentationAllowed(w, p, now) {
		return authorization.ErrDenied
	}
	s := p.Snapshot()
	objects, err := encodeObjectCeiling(w.Snapshot().Request.ObjectCeiling, a.tenantIssuer, w.Snapshot().Request.ResourceURI)
	if err != nil {
		return authorization.ErrDenied
	}
	var labels []consentLabelRecord
	for _, o := range s.Objects {
		labels = append(labels, consentLabelRecord{o.Type, o.Identifier, o.Name})
	}
	data, err := json.Marshal(labels)
	if err != nil {
		return authorization.ErrDenied
	}
	tag, err := a.tx.Exec(ctx, `INSERT INTO mayi.authorization_object_presentations(tenant_id,handle_hash,session_hash,subject,client_id,resource_uri,permission_version,object_ceiling,objects,presented_at)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10 WHERE EXISTS(SELECT 1 FROM mayi.authorization_transactions WHERE tenant_id=$1 AND handle_hash=$2 AND status='pending' AND expires_at>clock_timestamp())
 ON CONFLICT(tenant_id,handle_hash) DO NOTHING`, a.tenantIssuer.TenantID, s.AuthorizationHash, a.principal.SessionHash, s.Subject, s.ClientID, w.Snapshot().Request.ResourceURI, s.PermissionVersion, objects, data, now)
	if err != nil {
		return authorization.ErrUnavailable
	}
	stored, err := a.objectPresentation(ctx, w, now)
	if err != nil {
		return err
	}
	if !stored.Equal(p) {
		return authorization.ErrDenied
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	_, err = a.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,actor_id,object_ref) VALUES($1,'object_consent_presented',$2,$3)`, a.tenantIssuer.TenantID, a.principal.Subject, w.Snapshot().ID)
	return err
}

func (a *authorizationTransaction) objectPresentation(ctx context.Context, w domain.Transaction, now time.Time) (domain.ObjectConsentProjection, error) {
	s := w.Snapshot()
	if a.principal == nil || a.consentHash != s.HandleHash || s.Request.TenantIssuer != a.tenantIssuer || s.ConsentSessionHash != a.principal.SessionHash {
		return domain.ObjectConsentProjection{}, authorization.ErrDenied
	}
	p := domain.ObjectConsentSpec{}
	var objects, labels []byte
	var presented time.Time
	err := a.tx.QueryRow(ctx, `SELECT client_id,subject,permission_version,object_ceiling,objects,presented_at FROM mayi.authorization_object_presentations WHERE tenant_id=$1 AND handle_hash=$2 AND session_hash=$3 AND subject=$4`, a.tenantIssuer.TenantID, s.HandleHash, a.principal.SessionHash, a.principal.Subject).Scan(&p.ClientID, &p.Subject, &p.PermissionVersion, &objects, &labels, &presented)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ObjectConsentProjection{}, authorization.ErrDenied
	}
	if err != nil {
		return domain.ObjectConsentProjection{}, authorization.ErrUnavailable
	}
	if presented.Before(s.CreatedAt) || presented.After(now) || !presented.Before(s.ExpiresAt) || len(labels) > 131072 {
		return domain.ObjectConsentProjection{}, authorization.ErrDenied
	}
	p.AuthorizationHash = s.HandleHash
	p.Ceiling, err = decodeObjectCeiling(objects, a.tenantIssuer, s.Request.ResourceURI)
	if err != nil {
		return domain.ObjectConsentProjection{}, authorization.ErrDenied
	}
	var records []json.RawMessage
	if json.Unmarshal(labels, &records) != nil || len(records) > 32 {
		return domain.ObjectConsentProjection{}, authorization.ErrDenied
	}
	for _, record := range records {
		members, err := recordMembers(record, "type", "identifier", "name")
		if err != nil {
			return domain.ObjectConsentProjection{}, authorization.ErrDenied
		}
		var o domain.ConsentObject
		if json.Unmarshal(members["type"], &o.Type) != nil || json.Unmarshal(members["identifier"], &o.Identifier) != nil || json.Unmarshal(members["name"], &o.Name) != nil {
			return domain.ObjectConsentProjection{}, authorization.ErrDenied
		}
		p.Objects = append(p.Objects, o)
	}
	projection, err := domain.NewObjectConsentProjection(p)
	if err != nil || !projection.Matches(w, a.principal.Subject) {
		return domain.ObjectConsentProjection{}, authorization.ErrDenied
	}
	return projection, nil
}

func (a *authorizationTransaction) AuthorizeObjectApproval(ctx context.Context, w domain.Transaction, fresh domain.ObjectConsentProjection, now time.Time) (domain.ObjectConsentProjection, error) {
	a.objectApproval = nil
	if !a.presentationAllowed(w, fresh, now) {
		return domain.ObjectConsentProjection{}, authorization.ErrDenied
	}
	p, err := a.objectPresentation(ctx, w, now)
	if err != nil {
		return domain.ObjectConsentProjection{}, err
	}
	if !p.Equal(fresh) {
		return domain.ObjectConsentProjection{}, authorization.ErrDenied
	}
	a.objectApproval = &p
	return p, nil
}
