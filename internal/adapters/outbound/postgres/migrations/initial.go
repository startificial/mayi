// Package migrations contains append-only SQL migration sources.
package migrations

// Initial is the P0 transaction-proof schema. Migrations run explicitly with an
// owner role; application runtimes must use a separate non-owner/NOBYPASSRLS role.
const Initial = `
CREATE SCHEMA mayi;
CREATE TABLE mayi.tenants (
 tenant_id text PRIMARY KEY, issuer text NOT NULL UNIQUE,
 policy_version bigint NOT NULL CHECK (policy_version > 0)
);
CREATE TABLE mayi.clients (
 tenant_id text NOT NULL REFERENCES mayi.tenants, client_id text NOT NULL,
 enabled boolean NOT NULL DEFAULT true, PRIMARY KEY (tenant_id,client_id)
);
CREATE TABLE mayi.grants (
 tenant_id text NOT NULL, grant_id text NOT NULL, client_id text NOT NULL,
 subject text NOT NULL, principal_type text NOT NULL CHECK (principal_type IN ('user','machine')),
 resource text NOT NULL, current_scopes text[] NOT NULL, expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY (tenant_id,grant_id), FOREIGN KEY (tenant_id,client_id) REFERENCES mayi.clients
);
CREATE TABLE mayi.grant_revisions (
 tenant_id text NOT NULL, grant_id text NOT NULL, revision bigint NOT NULL CHECK (revision>0),
 scopes text[] NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id,grant_id,revision), FOREIGN KEY (tenant_id,grant_id) REFERENCES mayi.grants
);
CREATE FUNCTION mayi.reject_revision_mutation() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN RAISE EXCEPTION 'grant revisions are immutable'; END$$;
CREATE TRIGGER immutable_revision BEFORE UPDATE OR DELETE ON mayi.grant_revisions
 FOR EACH ROW EXECUTE FUNCTION mayi.reject_revision_mutation();
CREATE TABLE mayi.refresh_families (
 tenant_id text NOT NULL, family_id text NOT NULL, grant_id text NOT NULL, revision bigint NOT NULL,
 origin_code text NOT NULL, absolute_deadline timestamptz NOT NULL,
 idle_seconds integer NOT NULL CHECK (idle_seconds>0), revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY (tenant_id,family_id), UNIQUE (tenant_id,family_id,grant_id,revision),
 FOREIGN KEY (tenant_id,grant_id,revision) REFERENCES mayi.grant_revisions
);
CREATE FUNCTION mayi.reject_family_extension() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN RAISE EXCEPTION 'refresh family absolute lifetime cannot increase'; END$$;
CREATE TRIGGER family_lifetime_ceiling BEFORE UPDATE OF absolute_deadline ON mayi.refresh_families
 FOR EACH ROW WHEN (NEW.absolute_deadline > OLD.absolute_deadline)
 EXECUTE FUNCTION mayi.reject_family_extension();
CREATE TABLE mayi.credentials (
 tenant_id text NOT NULL, hash text NOT NULL, kind text NOT NULL CHECK(kind IN ('authorization_code','refresh_token')),
 grant_id text NOT NULL, revision bigint NOT NULL, resource text NOT NULL, client_id text NOT NULL,
 ceiling_scopes text[] NOT NULL, issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 pkce_challenge text NOT NULL DEFAULT '', redirect_uri text NOT NULL DEFAULT '', binding_thumbprint text NOT NULL DEFAULT '',
 origin_code text NOT NULL, family_id text, parent_issuance_id text,
 consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY (tenant_id,hash),
 FOREIGN KEY (tenant_id,grant_id,revision) REFERENCES mayi.grant_revisions,
 FOREIGN KEY (tenant_id,client_id) REFERENCES mayi.clients,
 FOREIGN KEY (tenant_id,origin_code) REFERENCES mayi.credentials(tenant_id,hash),
 FOREIGN KEY (tenant_id,family_id,grant_id,revision) REFERENCES mayi.refresh_families(tenant_id,family_id,grant_id,revision),
 CHECK (expires_at > issued_at),
 CHECK ((kind='authorization_code' AND family_id IS NULL AND origin_code=hash AND expires_at <= issued_at+interval '60 seconds') OR
        (kind='refresh_token' AND family_id IS NOT NULL))
);
CREATE TABLE mayi.revoked_code_lineages (
 tenant_id text NOT NULL, origin_code text NOT NULL,
 PRIMARY KEY(tenant_id,origin_code), FOREIGN KEY(tenant_id,origin_code) REFERENCES mayi.credentials(tenant_id,hash)
);
CREATE TABLE mayi.issuances (
 tenant_id text NOT NULL, issuance_id text NOT NULL, grant_id text NOT NULL, revision bigint NOT NULL,
 origin_code text NOT NULL, family_id text, parent_id text, source_credential text NOT NULL,
 resource text NOT NULL, scopes text[] NOT NULL, expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,issuance_id), UNIQUE(tenant_id,issuance_id,grant_id),
 FOREIGN KEY(tenant_id,grant_id,revision) REFERENCES mayi.grant_revisions,
 FOREIGN KEY(tenant_id,parent_id,grant_id) REFERENCES mayi.issuances(tenant_id,issuance_id,grant_id),
 FOREIGN KEY(tenant_id,source_credential) REFERENCES mayi.credentials(tenant_id,hash)
);
ALTER TABLE mayi.credentials ADD FOREIGN KEY(tenant_id,parent_issuance_id,grant_id)
 REFERENCES mayi.issuances(tenant_id,issuance_id,grant_id);
CREATE INDEX ON mayi.issuances(tenant_id,grant_id);
CREATE INDEX ON mayi.issuances(tenant_id,origin_code);
CREATE TABLE mayi.audit_events (
 event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id text NOT NULL REFERENCES mayi.tenants, event_type text NOT NULL,
 grant_id text NOT NULL, credential_hash text NOT NULL, issuance_id text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,grant_id) REFERENCES mayi.grants
);
CREATE TABLE mayi.proof_replays (
 tenant_id text NOT NULL REFERENCES mayi.tenants, thumbprint text NOT NULL,
 proof_id text NOT NULL, expires_at timestamptz NOT NULL, PRIMARY KEY(tenant_id,thumbprint,proof_id)
);
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['tenants','clients','grants','grant_revisions','refresh_families','credentials','revoked_code_lineages','issuances','audit_events','proof_replays'] LOOP
  EXECUTE format('ALTER TABLE mayi.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE mayi.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_scope ON mayi.%I USING (tenant_id = current_setting(''mayi.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''mayi.tenant_id'', true))',name);
 END LOOP;
END $policies$;
`
