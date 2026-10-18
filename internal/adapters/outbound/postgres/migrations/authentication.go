package migrations

// Authentication keeps explicit account mappings operator-owned. The runtime
// can create sessions and revoke handles, but cannot enroll members or remap
// identities. All session writers coordinate on the tenant before row locks.
const Authentication = `
CREATE TABLE mayi.external_identities (
 tenant_id text NOT NULL, provider_id text NOT NULL, upstream_issuer text NOT NULL,
 upstream_subject text NOT NULL CHECK(length(upstream_subject) BETWEEN 1 AND 255), subject text NOT NULL,
 PRIMARY KEY(tenant_id,provider_id,upstream_issuer,upstream_subject),
 FOREIGN KEY(tenant_id,subject) REFERENCES mayi.principal_memberships
);
CREATE TRIGGER coordinate_external_identity BEFORE INSERT OR UPDATE OR DELETE ON mayi.external_identities
 FOR EACH ROW EXECUTE FUNCTION mayi.coordinate_identity_mutation();
CREATE TABLE mayi.login_attempts (
 tenant_id text NOT NULL, state_hash text NOT NULL CHECK(state_hash ~ '^[0-9a-f]{64}$'),
 provider_id text NOT NULL, provider_hash text NOT NULL CHECK(provider_hash ~ '^[0-9a-f]{64}$'), authorization_hash text NOT NULL,
 browser_hash text NOT NULL CHECK(browser_hash ~ '^[0-9a-f]{64}$'),
 nonce_hash text NOT NULL CHECK(nonce_hash ~ '^[0-9a-f]{64}$'),
 verifier_hash text NOT NULL CHECK(verifier_hash ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 claimed_at timestamptz, completed_at timestamptz,
 PRIMARY KEY(tenant_id,state_hash), UNIQUE(tenant_id,authorization_hash),
 FOREIGN KEY(tenant_id,authorization_hash) REFERENCES mayi.authorization_transactions(tenant_id,handle_hash),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
 CHECK(claimed_at IS NULL OR claimed_at>=created_at AND claimed_at<expires_at),
 CHECK(completed_at IS NULL OR claimed_at IS NOT NULL AND completed_at>=claimed_at AND completed_at<expires_at)
);
CREATE TABLE mayi.session_authentication (
 tenant_id text NOT NULL, session_hash text NOT NULL, browser_hash text NOT NULL CHECK(browser_hash ~ '^[0-9a-f]{64}$'),
 provider_id text NOT NULL, upstream_issuer text NOT NULL, authenticated_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,session_hash),
 FOREIGN KEY(tenant_id,session_hash) REFERENCES mayi.browser_sessions
);
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['external_identities','login_attempts','session_authentication'] LOOP
  EXECUTE format('ALTER TABLE mayi.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE mayi.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_scope ON mayi.%I USING (tenant_id = current_setting(''mayi.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''mayi.tenant_id'', true))',name);
 END LOOP;
END $policies$;
`
