package migrations

const RequestBudgets = `
CREATE TABLE mayi.request_budgets(
 tenant_id text NOT NULL REFERENCES mayi.tenants,
 operation text NOT NULL CHECK(operation IN ('login','token','introspection')),
 dimension text NOT NULL CHECK(dimension IN ('ip','client','user')),
 key_hash text NOT NULL CHECK(key_hash ~ '^[0-9a-f]{64}$'),
 window_start timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 used integer NOT NULL CHECK(used>0 AND used<=1000000),
 PRIMARY KEY(tenant_id,operation,dimension,key_hash)
);
CREATE INDEX request_budget_expiry ON mayi.request_budgets(tenant_id,expires_at);
ALTER TABLE mayi.request_budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.request_budgets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.request_budgets USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
ALTER TABLE mayi.machine_authorizations ADD FOREIGN KEY(tenant_id,resource) REFERENCES mayi.resources(tenant_id,uri);
`
