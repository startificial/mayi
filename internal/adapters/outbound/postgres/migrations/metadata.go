package migrations

const Metadata = `
ALTER TABLE mayi.clients ADD COLUMN metadata_digest text NOT NULL DEFAULT '' CHECK(metadata_digest='' OR metadata_digest ~ '^[0-9a-f]{64}$');
ALTER TABLE mayi.clients ADD COLUMN metadata_policy_version bigint NOT NULL DEFAULT 0 CHECK(metadata_policy_version>=0);
ALTER TABLE mayi.clients ADD COLUMN metadata_resources text[] NOT NULL DEFAULT '{}';
ALTER TABLE mayi.clients ADD COLUMN metadata_types text[] NOT NULL DEFAULT '{}';
ALTER TABLE mayi.clients ADD CHECK((metadata_digest='')=(metadata_policy_version=0));
ALTER TABLE mayi.pushed_requests ADD COLUMN client_metadata_digest text NOT NULL DEFAULT '' CHECK(client_metadata_digest='' OR client_metadata_digest ~ '^[0-9a-f]{64}$');
ALTER TABLE mayi.authorization_transactions ADD COLUMN client_metadata_digest text NOT NULL DEFAULT '' CHECK(client_metadata_digest='' OR client_metadata_digest ~ '^[0-9a-f]{64}$');
ALTER TABLE mayi.credentials ADD COLUMN client_metadata_digest text NOT NULL DEFAULT '' CHECK(client_metadata_digest='' OR client_metadata_digest ~ '^[0-9a-f]{64}$');
ALTER TABLE mayi.issuances ADD COLUMN client_metadata_digest text NOT NULL DEFAULT '' CHECK(client_metadata_digest='' OR client_metadata_digest ~ '^[0-9a-f]{64}$');
CREATE TABLE mayi.client_metadata_policies (
 tenant_id text PRIMARY KEY REFERENCES mayi.tenants,version bigint NOT NULL CHECK(version>0),
 mode text NOT NULL CHECK(mode IN ('any','hosts','admin_only')),hosts text[] NOT NULL,approved_clients text[] NOT NULL,
 resources text[] NOT NULL,authorization_details_types text[] NOT NULL,redirect_approvals jsonb NOT NULL,
 max_clients integer NOT NULL CHECK(max_clients BETWEEN 0 AND 10000),access_token_seconds integer NOT NULL CHECK(access_token_seconds=0 OR access_token_seconds BETWEEN 60 AND 900)
);
CREATE TABLE mayi.client_metadata_state (
 tenant_id text NOT NULL,client_id text NOT NULL,generation bigint NOT NULL CHECK(generation>0),
 content_digest text NOT NULL CHECK(content_digest ~ '^[0-9a-f]{64}$'),authority_revision bigint NOT NULL CHECK(authority_revision>0),
 cache_document jsonb,etag text NOT NULL,last_modified text NOT NULL,fresh_until timestamptz,
 PRIMARY KEY(tenant_id,client_id),FOREIGN KEY(tenant_id,client_id) REFERENCES mayi.clients,
 CHECK(cache_document IS NOT NULL OR etag='' AND last_modified='' AND fresh_until IS NULL)
);
ALTER TABLE mayi.client_metadata_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.client_metadata_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.client_metadata_policies USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
ALTER TABLE mayi.client_metadata_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.client_metadata_state FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.client_metadata_state USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
ALTER TABLE mayi.request_budgets DROP CONSTRAINT request_budgets_operation_check;
ALTER TABLE mayi.request_budgets ADD CHECK(operation IN ('login','token','introspection','registration','cimd'));

-- Long exact URL identities must not overflow a composite btree key with a
-- 2048-byte RAR type. The digest is only an index key; all reads still compare
-- the complete tenant/client/type identity, never its digest alone.
ALTER TABLE mayi.client_object_types DROP CONSTRAINT client_object_types_pkey;
CREATE UNIQUE INDEX client_object_types_identity ON mayi.client_object_types(tenant_id,sha256(client_id::bytea),type_uri);
`
