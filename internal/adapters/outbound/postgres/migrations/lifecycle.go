package migrations

// Lifecycle supplies the live P2 contracts. Earlier proof migrations remain
// immutable; no deployed legacy conversion is supported by the preview.
const Lifecycle = `
ALTER TABLE mayi.clients ADD COLUMN auth_version bigint NOT NULL DEFAULT 1 CHECK(auth_version>0);
ALTER TABLE mayi.clients ADD COLUMN auth_method text NOT NULL DEFAULT 'none' CHECK(auth_method IN ('none','client_secret_basic','private_key_jwt'));
ALTER TABLE mayi.clients ADD COLUMN introspection boolean NOT NULL DEFAULT false;
ALTER TABLE mayi.clients ADD COLUMN machine boolean NOT NULL DEFAULT false;
ALTER TABLE mayi.clients ADD CONSTRAINT introspection_requires_confidential CHECK(NOT introspection OR auth_method IN ('client_secret_basic','private_key_jwt'));
ALTER TABLE mayi.clients ADD CONSTRAINT machine_identity CHECK(NOT machine OR (client_id LIKE 'client:%' AND auth_method IN ('client_secret_basic','private_key_jwt') AND cardinality(redirect_uris)=0));
ALTER TABLE mayi.clients ADD COLUMN jwks jsonb;
ALTER TABLE mayi.clients ADD COLUMN jwks_uri text NOT NULL DEFAULT '';
ALTER TABLE mayi.resources ADD COLUMN token_format text NOT NULL DEFAULT 'jwt' CHECK(token_format IN ('jwt','opaque'));
ALTER TABLE mayi.resource_scopes ADD COLUMN requires_admin boolean NOT NULL DEFAULT false;
ALTER TABLE mayi.tenant_policies ADD COLUMN refresh_idle_seconds integer NOT NULL DEFAULT 86400 CHECK(refresh_idle_seconds BETWEEN 60 AND 2592000);
ALTER TABLE mayi.tenant_policies ADD COLUMN refresh_absolute_seconds integer NOT NULL DEFAULT 2592000 CHECK(refresh_absolute_seconds BETWEEN refresh_idle_seconds AND 31622400);
ALTER TABLE mayi.browser_sessions ADD COLUMN last_used_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE mayi.browser_sessions ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE mayi.refresh_families ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE mayi.grants ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE mayi.issuances ALTER COLUMN origin_code DROP NOT NULL;
ALTER TABLE mayi.issuances ALTER COLUMN source_credential DROP NOT NULL;
ALTER TABLE mayi.issuances ADD COLUMN token_hash text;
ALTER TABLE mayi.issuances ADD COLUMN issued_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE mayi.issuances ADD COLUMN binding_thumbprint text NOT NULL DEFAULT '';
ALTER TABLE mayi.issuances ADD COLUMN signing_version integer NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX issuance_token_hash ON mayi.issuances(tenant_id,token_hash) WHERE token_hash IS NOT NULL;
CREATE TABLE mayi.authorization_options (
 tenant_id text NOT NULL, handle_hash text NOT NULL, oidc boolean NOT NULL,
 nonce text NOT NULL, offline_access boolean NOT NULL,
 PRIMARY KEY(tenant_id,handle_hash), FOREIGN KEY(tenant_id,handle_hash) REFERENCES mayi.authorization_transactions,
 CHECK((oidc AND octet_length(nonce) BETWEEN 16 AND 256) OR (NOT oidc AND nonce=''))
);
CREATE TABLE mayi.pushed_options (
 tenant_id text NOT NULL, reference_hash text NOT NULL, oidc boolean NOT NULL,
 nonce text NOT NULL, offline_access boolean NOT NULL,
 PRIMARY KEY(tenant_id,reference_hash), FOREIGN KEY(tenant_id,reference_hash) REFERENCES mayi.pushed_requests,
 CHECK((oidc AND octet_length(nonce) BETWEEN 16 AND 256) OR (NOT oidc AND nonce=''))
);
CREATE TABLE mayi.client_secrets (
 tenant_id text NOT NULL, client_id text NOT NULL, secret_hash text NOT NULL,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,client_id,secret_hash), FOREIGN KEY(tenant_id,client_id) REFERENCES mayi.clients
);
CREATE TABLE mayi.machine_authorizations (
 tenant_id text NOT NULL, client_id text NOT NULL, resource text NOT NULL,
 scopes text[] NOT NULL, object_ceiling jsonb NOT NULL CHECK(mayi.valid_object_ceiling(object_ceiling)),
 PRIMARY KEY(tenant_id,client_id,resource), FOREIGN KEY(tenant_id,client_id) REFERENCES mayi.clients,
 CHECK(object_ceiling->>'resource'=resource)
);
CREATE FUNCTION mayi.immutable_authorization_options() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN RAISE EXCEPTION 'authorization options are immutable'; END$$;
CREATE TRIGGER immutable_options BEFORE UPDATE OR DELETE ON mayi.authorization_options FOR EACH ROW EXECUTE FUNCTION mayi.immutable_authorization_options();
CREATE TRIGGER immutable_pushed_options BEFORE UPDATE OR DELETE ON mayi.pushed_options FOR EACH ROW EXECUTE FUNCTION mayi.immutable_authorization_options();
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['authorization_options','pushed_options','client_secrets','machine_authorizations'] LOOP
  EXECUTE format('ALTER TABLE mayi.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE mayi.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_scope ON mayi.%I USING (tenant_id=current_setting(''mayi.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''mayi.tenant_id'',true))',name);
 END LOOP;
END $policies$;
REVOKE ALL ON FUNCTION mayi.immutable_authorization_options() FROM PUBLIC;
`
