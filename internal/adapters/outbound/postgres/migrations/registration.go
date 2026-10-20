package migrations

const Registration = `
CREATE TABLE mayi.client_registration_policies (
 tenant_id text PRIMARY KEY REFERENCES mayi.tenants,
 version bigint NOT NULL CHECK(version>0), mode text NOT NULL CHECK(mode IN ('admin_only','open')),
 resources text[] NOT NULL, authorization_details_types text[] NOT NULL,
 max_clients integer NOT NULL CHECK(max_clients BETWEEN 0 AND 10000),
 access_token_seconds integer NOT NULL CHECK(access_token_seconds=0 OR access_token_seconds BETWEEN 60 AND 900),
 require_initial_access boolean NOT NULL,
 CHECK(mode<>'open' OR cardinality(resources) BETWEEN 1 AND 32 AND cardinality(authorization_details_types) BETWEEN 1 AND 32 AND max_clients>0 AND access_token_seconds>=60)
);
CREATE TABLE mayi.dynamic_clients (
 tenant_id text NOT NULL, client_id text NOT NULL,
 PRIMARY KEY(tenant_id,client_id), FOREIGN KEY(tenant_id,client_id) REFERENCES mayi.clients(tenant_id,client_id)
);
ALTER TABLE mayi.client_registration_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.client_registration_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.client_registration_policies USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
ALTER TABLE mayi.dynamic_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.dynamic_clients FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.dynamic_clients USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
ALTER TABLE mayi.request_budgets DROP CONSTRAINT request_budgets_operation_check;
ALTER TABLE mayi.request_budgets ADD CHECK(operation IN ('login','token','introspection','registration'));
`
