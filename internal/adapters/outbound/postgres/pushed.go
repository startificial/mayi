package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/services/authorization"
)

func (a *authorizationTransaction) CreatePushed(ctx context.Context, p domain.PushedRequest) error {
	s := p.Snapshot()
	if _, err := domain.NewPushed(s); err != nil || s.Request.TenantIssuer != a.tenantIssuer || s.PolicyVersion != a.version || s.AuthorizationHash != "" {
		return authorization.ErrInvalid
	}
	r := s.Request
	objects, err := encodeObjectCeiling(r.ObjectCeiling, a.tenantIssuer, r.ResourceURI)
	if err != nil || objects == nil {
		return authorization.ErrInvalid
	}
	tag, err := a.tx.Exec(ctx, `INSERT INTO mayi.pushed_requests(tenant_id,reference_hash,request_id,client_id,redirect_uri,resource_uri,permission_scopes,pkce_challenge,binding_thumbprint,client_state,object_ceiling,policy_version,created_at,expires_at)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14 WHERE $14>clock_timestamp()`, a.tenantIssuer.TenantID, s.ReferenceHash, s.ID, r.ClientID, r.RedirectURI, r.ResourceURI, r.PermissionScopes, r.PKCEChallenge, r.BindingThumbprint, r.State, objects, s.PolicyVersion, s.CreatedAt, s.ExpiresAt)
	if err != nil || tag.RowsAffected() != 1 {
		return authorization.ErrUnavailable
	}
	_, err = a.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,object_ref) VALUES($1,'authorization_pushed',$2)`, a.tenantIssuer.TenantID, s.ID)
	return err
}

func (a *authorizationTransaction) AuthorizePushed(ctx context.Context, proof authorization.PushedProof, now time.Time) error {
	a.pushed = nil
	if !proof.Valid() || proof.TenantIssuer != a.tenantIssuer || now.IsZero() {
		return authorization.ErrDenied
	}
	var hash string
	err := a.tx.QueryRow(ctx, `SELECT p.reference_hash FROM mayi.pushed_requests p JOIN mayi.clients c USING(tenant_id,client_id)
 WHERE p.tenant_id=$1 AND p.reference_hash=$2 AND p.client_id=$3 AND c.enabled AND p.policy_version=$4
 AND p.consumed_at IS NULL AND p.created_at<=$5 AND p.expires_at>$5 AND p.expires_at>clock_timestamp()
 FOR UPDATE OF p FOR SHARE OF c`, a.tenantIssuer.TenantID, proof.ReferenceHash, proof.ClientID, a.version, now).Scan(&hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authorization.ErrDenied
		}
		return authorization.ErrUnavailable
	}
	a.pushed = &proof
	return nil
}

func (a *authorizationTransaction) Pushed(ctx context.Context, hash string) (domain.PushedRequest, error) {
	if a.pushed == nil || hash != a.pushed.ReferenceHash {
		return domain.PushedRequest{}, authorization.ErrDenied
	}
	s := domain.PushedSpec{}
	s.Request.TenantIssuer = a.tenantIssuer
	var objects []byte
	var consumed *time.Time
	err := a.tx.QueryRow(ctx, `SELECT request_id,reference_hash,client_id,redirect_uri,resource_uri,permission_scopes,pkce_challenge,binding_thumbprint,client_state,object_ceiling,policy_version,created_at,expires_at,COALESCE(authorization_hash,''),consumed_at
 FROM mayi.pushed_requests WHERE tenant_id=$1 AND reference_hash=$2 AND client_id=$3`, a.tenantIssuer.TenantID, hash, a.pushed.ClientID).Scan(&s.ID, &s.ReferenceHash, &s.Request.ClientID, &s.Request.RedirectURI, &s.Request.ResourceURI, &s.Request.PermissionScopes, &s.Request.PKCEChallenge, &s.Request.BindingThumbprint, &s.Request.State, &objects, &s.PolicyVersion, &s.CreatedAt, &s.ExpiresAt, &s.AuthorizationHash, &consumed)
	if err != nil {
		return domain.PushedRequest{}, authorization.ErrUnavailable
	}
	if consumed != nil {
		s.ConsumedAt = *consumed
	}
	s.Request.ObjectCeiling, err = decodeObjectCeiling(objects, a.tenantIssuer, s.Request.ResourceURI)
	if err != nil {
		return domain.PushedRequest{}, authorization.ErrDenied
	}
	p, err := domain.NewPushed(s)
	if err != nil {
		return domain.PushedRequest{}, authorization.ErrDenied
	}
	return p, nil
}

func (a *authorizationTransaction) ConsumePushed(ctx context.Context, next domain.PushedRequest, workflow domain.Transaction, now time.Time) error {
	p, w := next.Snapshot(), workflow.Snapshot()
	if _, err := domain.NewPushed(p); err != nil || a.pushed == nil || p.ReferenceHash != a.pushed.ReferenceHash || p.Request.TenantIssuer != a.tenantIssuer || p.Request.ClientID != a.pushed.ClientID || w.PushedRequestHash != p.ReferenceHash || w.HandleHash != p.AuthorizationHash || w.BrowserBindingHash != a.pushed.BrowserBindingHash || !p.Request.Equal(w.Request) || p.PolicyVersion != w.PolicyVersion || p.PolicyVersion != a.version || !p.ConsumedAt.Equal(now) || !w.CreatedAt.Equal(now) || w.Status != domain.Pending {
		return authorization.ErrDenied
	}
	if err := a.CreateAuthorization(ctx, workflow); err != nil {
		return err
	}
	r := p.Request
	objects, err := encodeObjectCeiling(r.ObjectCeiling, a.tenantIssuer, r.ResourceURI)
	if err != nil {
		return authorization.ErrDenied
	}
	tag, err := a.tx.Exec(ctx, `UPDATE mayi.pushed_requests SET consumed_at=$4,authorization_hash=$5
 WHERE tenant_id=$1 AND reference_hash=$2 AND client_id=$3 AND consumed_at IS NULL AND created_at<=$4 AND expires_at>$4 AND expires_at>clock_timestamp()
 AND request_id=$6 AND policy_version=$7 AND redirect_uri=$8 AND resource_uri=$9 AND permission_scopes=$10 AND pkce_challenge=$11 AND binding_thumbprint=$12 AND client_state=$13 AND object_ceiling=$14::jsonb AND created_at=$15 AND expires_at=$16`, a.tenantIssuer.TenantID, p.ReferenceHash, r.ClientID, now, w.HandleHash, p.ID, p.PolicyVersion, r.RedirectURI, r.ResourceURI, r.PermissionScopes, r.PKCEChallenge, r.BindingThumbprint, r.State, objects, p.CreatedAt, p.ExpiresAt)
	if err != nil {
		return authorization.ErrUnavailable
	}
	if tag.RowsAffected() != 1 {
		return authorization.ErrDenied
	}
	_, err = a.tx.Exec(ctx, `INSERT INTO mayi.audit_events(tenant_id,event_type,object_ref) VALUES($1,'pushed_authorization_used',$2)`, a.tenantIssuer.TenantID, p.ID)
	return err
}
