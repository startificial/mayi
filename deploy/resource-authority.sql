-- Resource-owner contract v1. Install with the resource owner's migration role,
-- in the SAME PostgreSQL database as Mayi, never with Mayi's runtime login.
-- These are authoritative, synchronously maintained projections, not a cache.
BEGIN;
CREATE SCHEMA mayi_resource;
REVOKE ALL ON SCHEMA mayi_resource FROM PUBLIC;

CREATE TABLE mayi_resource.authorities (
  tenant_id text NOT NULL,
  issuer text NOT NULL,
  resource text NOT NULL,
  subject text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  lock_marker boolean NOT NULL DEFAULT false CHECK (NOT lock_marker),
  PRIMARY KEY (tenant_id,issuer,resource,subject)
);
CREATE TABLE mayi_resource.permissions (
  tenant_id text NOT NULL,
  issuer text NOT NULL,
  resource text NOT NULL,
  subject text NOT NULL,
  object_type text NOT NULL,
  identifier text NOT NULL,
  actions text[] NOT NULL CHECK (cardinality(actions) BETWEEN 1 AND 16),
  PRIMARY KEY (tenant_id,issuer,resource,subject,object_type,identifier),
  FOREIGN KEY (tenant_id,issuer,resource,subject)
    REFERENCES mayi_resource.authorities ON DELETE RESTRICT
);
CREATE TABLE mayi_resource.labels (
  tenant_id text NOT NULL,
  issuer text NOT NULL,
  resource text NOT NULL,
  object_type text NOT NULL,
  identifier text NOT NULL,
  name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 256),
  lock_marker boolean NOT NULL DEFAULT false CHECK (NOT lock_marker),
  PRIMARY KEY (tenant_id,issuer,resource,object_type,identifier)
);

-- Permission writers MUST lock the authority root before touching child rows.
-- This trigger additionally guarantees that direct DML cannot skip coordination
-- or the permission version bump. Lock-order violations may abort as deadlocks;
-- they cannot commit an unguarded permission change.
CREATE FUNCTION mayi_resource.permission_changed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, mayi_resource AS $$
DECLARE item record;
BEGIN
  IF TG_OP = 'UPDATE' AND
     (NEW.tenant_id,NEW.issuer,NEW.resource,NEW.subject,NEW.object_type,NEW.identifier)
     IS DISTINCT FROM
     (OLD.tenant_id,OLD.issuer,OLD.resource,OLD.subject,OLD.object_type,OLD.identifier) THEN
    RAISE EXCEPTION 'permission identity is immutable';
  END IF;
  IF TG_OP = 'DELETE' THEN item := OLD; ELSE item := NEW; END IF;
  UPDATE mayi_resource.authorities SET version=version+1
   WHERE tenant_id=item.tenant_id AND issuer=item.issuer
     AND resource=item.resource AND subject=item.subject;
  IF NOT FOUND THEN RAISE EXCEPTION 'authority required'; END IF;
  RETURN item;
END $$;
CREATE TRIGGER permission_changed BEFORE INSERT OR UPDATE OR DELETE
 ON mayi_resource.permissions FOR EACH ROW EXECUTE FUNCTION mayi_resource.permission_changed();

CREATE FUNCTION mayi_resource.authority_changed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, mayi_resource AS $$
BEGIN
  IF (NEW.tenant_id,NEW.issuer,NEW.resource,NEW.subject) IS DISTINCT FROM
     (OLD.tenant_id,OLD.issuer,OLD.resource,OLD.subject) THEN
    RAISE EXCEPTION 'authority identity is immutable';
  END IF;
  NEW.version := OLD.version+1;
  RETURN NEW;
END $$;
CREATE TRIGGER authority_changed BEFORE UPDATE ON mayi_resource.authorities
 FOR EACH ROW EXECUTE FUNCTION mayi_resource.authority_changed();

ALTER TABLE mayi_resource.authorities ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi_resource.authorities FORCE ROW LEVEL SECURITY;
ALTER TABLE mayi_resource.permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi_resource.permissions FORCE ROW LEVEL SECURITY;
ALTER TABLE mayi_resource.labels ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi_resource.labels FORCE ROW LEVEL SECURITY;
CREATE POLICY authority_scope ON mayi_resource.authorities USING (
  tenant_id=current_setting('mayi_resource.tenant_id',true) AND
  issuer=current_setting('mayi_resource.issuer',true) AND
  resource=current_setting('mayi_resource.resource',true));
CREATE POLICY permission_scope ON mayi_resource.permissions USING (
  tenant_id=current_setting('mayi_resource.tenant_id',true) AND
  issuer=current_setting('mayi_resource.issuer',true) AND
  resource=current_setting('mayi_resource.resource',true));
CREATE POLICY label_scope ON mayi_resource.labels USING (
  tenant_id=current_setting('mayi_resource.tenant_id',true) AND
  issuer=current_setting('mayi_resource.issuer',true) AND
  resource=current_setting('mayi_resource.resource',true));
REVOKE ALL ON ALL TABLES IN SCHEMA mayi_resource FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mayi_resource FROM PUBLIC;
COMMIT;

-- The owner explicitly grants a restricted Mayi runtime role:
-- GRANT USAGE ON SCHEMA mayi_resource TO mayi_runtime;
-- GRANT SELECT ON ALL TABLES IN SCHEMA mayi_resource TO mayi_runtime;
-- PostgreSQL requires an UPDATE privilege for SELECT FOR SHARE. Grant only the
-- inert marker columns, never ACLs, enabled, version, identity or label content:
-- GRANT UPDATE(lock_marker) ON mayi_resource.authorities,mayi_resource.labels TO mayi_runtime;
-- Application writers need their own reviewed grants and tenant context. Do not
-- grant TRUNCATE, trigger disabling, schema ownership or owner membership to Mayi.
