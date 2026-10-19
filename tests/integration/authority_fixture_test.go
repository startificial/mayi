package integration_test

import (
	"context"
	"github.com/jackc/pgx/v5"
	"testing"
)

// These are explicit trusted operator fixtures for transaction tests. They retain
// full PAR, session, presentation and approval correlation; none is a production
// default or an alternative authorization path.
const fixtureObjectJSON = `{"version":1,"semantics":"object-actions-v1","resource":"https://api.example","details":[{"type":"https://api.example/types/fixture/v1","identifier":"123","actions":["read"]}]}`

func seedCodeApproval(t *testing.T, tx pgx.Tx, tenant, hash string) {
	t.Helper()
	ctx := context.Background()
	ref, handle, csrf, browser, session := secretHash(tenant+hash+"par"), secretHash(tenant+hash+"workflow"), secretHash(tenant+hash+"csrf"), secretHash(tenant+hash+"browser"), secretHash(tenant+hash+"session")
	// The code has already been inserted in this transaction; its deferred
	// provenance constraint is checked only after this complete snapshot exists.
	_, err := tx.Exec(ctx, `INSERT INTO mayi.principal_memberships(tenant_id,subject)
 SELECT tenant_id,subject FROM mayi.grants WHERE tenant_id=$1 AND grant_id=(SELECT grant_id FROM mayi.credentials WHERE tenant_id=$1 AND hash=$2) ON CONFLICT DO NOTHING;
 `, tenant, hash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO mayi.browser_sessions(tenant_id,session_hash,subject,expires_at)
 SELECT tenant_id,$3,subject,clock_timestamp()+interval '1 hour' FROM mayi.grants WHERE tenant_id=$1 AND grant_id=(SELECT grant_id FROM mayi.credentials WHERE tenant_id=$1 AND hash=$2)`, tenant, hash, session)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO mayi.pushed_requests(tenant_id,reference_hash,request_id,client_id,redirect_uri,resource_uri,permission_scopes,pkce_challenge,binding_thumbprint,client_state,object_ceiling,policy_version,created_at,expires_at)
 SELECT c.tenant_id,$3,$3,c.client_id,c.redirect_uri,c.resource,c.ceiling_scopes,c.pkce_challenge,c.binding_thumbprint,'fixture-state-at-least-16',c.object_ceiling,t.policy_version,c.issued_at,c.issued_at+interval '90 seconds'
 FROM mayi.credentials c JOIN mayi.tenants t USING(tenant_id) WHERE c.tenant_id=$1 AND c.hash=$2`, tenant, hash, ref)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO mayi.pushed_options VALUES($1,$2,false,'',false)`, tenant, ref)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO mayi.authorization_transactions(tenant_id,handle_hash,authorization_id,browser_binding_hash,csrf_hash,client_id,redirect_uri,resource_uri,permission_scopes,pkce_challenge,binding_thumbprint,client_state,policy_version,created_at,expires_at,status,object_ceiling,pushed_request_hash,consent_session_hash)
 SELECT tenant_id,$3,$3,$4,$5,client_id,redirect_uri,resource_uri,permission_scopes,pkce_challenge,binding_thumbprint,client_state,policy_version,created_at,created_at+interval '5 minutes','pending',object_ceiling,reference_hash,$6
 FROM mayi.pushed_requests WHERE tenant_id=$1 AND reference_hash=$2`, tenant, ref, handle, browser, csrf, session)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO mayi.authorization_options VALUES($1,$2,false,'',false)`, tenant, handle)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO mayi.authorization_object_presentations(tenant_id,handle_hash,session_hash,subject,client_id,resource_uri,permission_version,object_ceiling,objects,presented_at)
 SELECT w.tenant_id,w.handle_hash,w.consent_session_hash,g.subject,w.client_id,w.resource_uri,1,w.object_ceiling,
 (SELECT jsonb_agg(jsonb_build_object('type',d->>'type','identifier',d->>'identifier','name','Fixture object')) FROM jsonb_array_elements(w.object_ceiling->'details') d),w.created_at
 FROM mayi.authorization_transactions w JOIN mayi.credentials c ON c.tenant_id=w.tenant_id AND c.hash=$2 JOIN mayi.grants g ON g.tenant_id=c.tenant_id AND g.grant_id=c.grant_id WHERE w.tenant_id=$1 AND w.handle_hash=$3`, tenant, hash, handle)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `UPDATE mayi.authorization_transactions w SET status='approved',subject=g.subject,grant_id=g.grant_id,code_hash=c.hash,decided_at=w.created_at
 FROM mayi.credentials c JOIN mayi.grants g USING(tenant_id,grant_id) WHERE w.tenant_id=$1 AND w.handle_hash=$3 AND c.tenant_id=$1 AND c.hash=$2`, tenant, hash, handle)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `UPDATE mayi.pushed_requests SET consumed_at=created_at,authorization_hash=$3 WHERE tenant_id=$1 AND reference_hash=$2`, tenant, ref, handle)
	if err != nil {
		t.Fatal(err)
	}
}
