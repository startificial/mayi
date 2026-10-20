package migrations

const DPoP = `
ALTER TABLE mayi.clients ADD COLUMN require_binding boolean NOT NULL DEFAULT false;
CREATE TABLE mayi.proof_nonces (
 tenant_id text NOT NULL REFERENCES mayi.tenants, purpose text NOT NULL CHECK(purpose IN ('token','resource')),
 target text NOT NULL CHECK(octet_length(target) BETWEEN 1 AND 2048), thumbprint text NOT NULL CHECK(octet_length(thumbprint)=43),
 nonce_hash text NOT NULL CHECK(nonce_hash ~ '^[0-9a-f]{64}$'), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,nonce_hash)
);
CREATE INDEX proof_nonce_expiry ON mayi.proof_nonces(tenant_id,expires_at);
CREATE INDEX proof_replay_expiry ON mayi.proof_replays(tenant_id,expires_at);
ALTER TABLE mayi.proof_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.proof_nonces FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.proof_nonces USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
`
