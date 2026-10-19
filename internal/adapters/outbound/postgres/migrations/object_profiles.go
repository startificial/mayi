package migrations

// ObjectProfiles registers immutable resource-owned semantics separately from
// approved authority snapshots. It enables no public RAR or PAR flow.
const ObjectProfiles = `
ALTER TABLE mayi.resources ADD CONSTRAINT resource_identity_uri UNIQUE(tenant_id,resource_id,uri);
CREATE TABLE mayi.resource_object_profiles (
 tenant_id text NOT NULL, resource_id text NOT NULL, resource_uri text NOT NULL,
 type_uri text NOT NULL, semantics text NOT NULL CHECK(semantics='object-actions-v1'),
 actions jsonb NOT NULL CHECK(jsonb_typeof(actions)='object' AND actions<>'{}'::jsonb AND octet_length(actions::text)<=16384),
 PRIMARY KEY(tenant_id,type_uri),
 FOREIGN KEY(tenant_id,resource_id,resource_uri) REFERENCES mayi.resources(tenant_id,resource_id,uri)
);
ALTER TABLE mayi.resource_object_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.resource_object_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.resource_object_profiles
 USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
CREATE FUNCTION mayi.reject_profile_mutation() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN RAISE EXCEPTION 'registered object profiles are immutable'; END$$;
CREATE TRIGGER immutable_object_profile BEFORE UPDATE OR DELETE ON mayi.resource_object_profiles
 FOR EACH ROW EXECUTE FUNCTION mayi.reject_profile_mutation();
REVOKE ALL ON FUNCTION mayi.reject_profile_mutation() FROM PUBLIC;
`
