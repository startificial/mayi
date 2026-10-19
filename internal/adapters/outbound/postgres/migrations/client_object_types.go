package migrations

// ClientObjectTypes binds each allowed type to a registered resource that the
// client may request. Raw P0 proof rows are not a supported registration flow.
const ClientObjectTypes = `
ALTER TABLE mayi.resource_object_profiles ADD CONSTRAINT profile_resource_type UNIQUE(tenant_id,resource_id,type_uri);
CREATE TABLE mayi.client_object_types (
 tenant_id text NOT NULL, client_id text NOT NULL, resource_id text NOT NULL, type_uri text NOT NULL,
 PRIMARY KEY(tenant_id,client_id,type_uri),
 FOREIGN KEY(tenant_id,client_id,resource_id) REFERENCES mayi.client_resources,
 FOREIGN KEY(tenant_id,resource_id,type_uri) REFERENCES mayi.resource_object_profiles(tenant_id,resource_id,type_uri)
);
ALTER TABLE mayi.client_object_types ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.client_object_types FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.client_object_types
 USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
CREATE FUNCTION mayi.reject_client_type_mutation() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN RAISE EXCEPTION 'registered client type bindings are immutable'; END$$;
CREATE TRIGGER immutable_client_object_type BEFORE UPDATE OR DELETE ON mayi.client_object_types
 FOR EACH ROW EXECUTE FUNCTION mayi.reject_client_type_mutation();
REVOKE ALL ON FUNCTION mayi.reject_client_type_mutation() FROM PUBLIC;
`
