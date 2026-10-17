package migrations

// Foundation expands the P0 schema without replacing its immutable history.
const Foundation = `
CREATE FUNCTION mayi.reject_issuer_change() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN RAISE EXCEPTION 'tenant issuer and identity are immutable'; END$$;
CREATE TRIGGER immutable_issuer BEFORE UPDATE OF tenant_id,issuer ON mayi.tenants
 FOR EACH ROW WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.issuer IS DISTINCT FROM NEW.issuer)
 EXECUTE FUNCTION mayi.reject_issuer_change();
CREATE TABLE mayi.tenant_policies (
 tenant_id text PRIMARY KEY REFERENCES mayi.tenants,
 max_access_token_seconds integer NOT NULL CHECK(max_access_token_seconds BETWEEN 60 AND 900),
 max_grant_seconds integer NOT NULL CHECK(max_grant_seconds BETWEEN max_access_token_seconds AND 31622400),
 require_binding boolean NOT NULL
);
CREATE TABLE mayi.resources (
 tenant_id text NOT NULL REFERENCES mayi.tenants, resource_id text NOT NULL,
 uri text NOT NULL, name text NOT NULL, access_token_seconds integer NOT NULL CHECK(access_token_seconds BETWEEN 60 AND 900),
 require_binding boolean NOT NULL,
 PRIMARY KEY(tenant_id,resource_id), UNIQUE(tenant_id,uri)
);
CREATE TABLE mayi.resource_scopes (
 tenant_id text NOT NULL, resource_id text NOT NULL, name text NOT NULL, description text NOT NULL,
 PRIMARY KEY(tenant_id,resource_id,name), FOREIGN KEY(tenant_id,resource_id) REFERENCES mayi.resources
);
ALTER TABLE mayi.clients ADD COLUMN name text NOT NULL DEFAULT '';
ALTER TABLE mayi.clients ADD COLUMN redirect_uris text[] NOT NULL DEFAULT '{}';
ALTER TABLE mayi.clients ADD COLUMN access_token_seconds integer NOT NULL DEFAULT 600 CHECK(access_token_seconds BETWEEN 60 AND 900);
CREATE TABLE mayi.client_resources (
 tenant_id text NOT NULL, client_id text NOT NULL, resource_id text NOT NULL,
 PRIMARY KEY(tenant_id,client_id,resource_id),
 FOREIGN KEY(tenant_id,client_id) REFERENCES mayi.clients,
 FOREIGN KEY(tenant_id,resource_id) REFERENCES mayi.resources
);
CREATE TABLE mayi.signing_keys (
 tenant_id text NOT NULL REFERENCES mayi.tenants, version integer NOT NULL CHECK(version>0),
 key_id text NOT NULL UNIQUE, x text NOT NULL, y text NOT NULL,
 published_at timestamptz NOT NULL, active boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,version), UNIQUE(x,y)
);
CREATE UNIQUE INDEX one_active_signing_key ON mayi.signing_keys(tenant_id) WHERE active;
ALTER TABLE mayi.audit_events ALTER COLUMN grant_id DROP NOT NULL;
ALTER TABLE mayi.audit_events ALTER COLUMN credential_hash DROP NOT NULL;
ALTER TABLE mayi.audit_events ADD COLUMN actor_id text NOT NULL DEFAULT '';
ALTER TABLE mayi.audit_events ADD COLUMN object_ref text NOT NULL DEFAULT '';
ALTER TABLE mayi.audit_events ADD CONSTRAINT audit_tenant_event UNIQUE(tenant_id,event_id);
CREATE TABLE mayi.outbox_events (
 tenant_id text NOT NULL, event_id bigint NOT NULL, attempts bigint NOT NULL DEFAULT 0,
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(), delivered_at timestamptz,
 PRIMARY KEY(tenant_id,event_id), FOREIGN KEY(tenant_id,event_id) REFERENCES mayi.audit_events(tenant_id,event_id)
);
CREATE INDEX pending_outbox ON mayi.outbox_events(tenant_id,available_at,event_id) WHERE delivered_at IS NULL;
CREATE FUNCTION mayi.enqueue_audit() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN INSERT INTO mayi.outbox_events(tenant_id,event_id) VALUES(NEW.tenant_id,NEW.event_id); RETURN NEW; END$$;
CREATE TRIGGER audit_outbox AFTER INSERT ON mayi.audit_events FOR EACH ROW EXECUTE FUNCTION mayi.enqueue_audit();
CREATE FUNCTION mayi.reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN RAISE EXCEPTION 'audit events are append only'; END$$;
CREATE TRIGGER immutable_audit BEFORE UPDATE OR DELETE ON mayi.audit_events FOR EACH ROW EXECUTE FUNCTION mayi.reject_audit_mutation();
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['tenant_policies','resources','resource_scopes','client_resources','signing_keys','outbox_events'] LOOP
  EXECUTE format('ALTER TABLE mayi.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE mayi.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_scope ON mayi.%I USING (tenant_id = current_setting(''mayi.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''mayi.tenant_id'', true))',name);
 END LOOP;
END $policies$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mayi FROM PUBLIC;
`
