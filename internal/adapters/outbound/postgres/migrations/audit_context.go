package migrations

const AuditContext = `
ALTER TABLE mayi.audit_events ADD COLUMN request_id text NOT NULL DEFAULT '' CHECK(request_id='' OR request_id ~ '^[0-9a-f]{32}$');
ALTER TABLE mayi.audit_events ADD COLUMN remote_ip text NOT NULL DEFAULT '' CHECK(octet_length(remote_ip)<=45);
ALTER TABLE mayi.audit_events ADD COLUMN user_agent text NOT NULL DEFAULT '' CHECK(octet_length(user_agent)<=512);
ALTER TABLE mayi.audit_events ADD COLUMN user_id text NOT NULL DEFAULT '';
ALTER TABLE mayi.audit_events ADD COLUMN client_id text NOT NULL DEFAULT '';
ALTER TABLE mayi.audit_events ADD COLUMN resource text NOT NULL DEFAULT '';
ALTER TABLE mayi.audit_events ADD COLUMN status_code integer NOT NULL DEFAULT 0;
CREATE FUNCTION mayi.audit_request_context() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 NEW.request_id:=COALESCE(current_setting('mayi.request_id',true),'');
 NEW.remote_ip:=COALESCE(current_setting('mayi.remote_ip',true),'');
 NEW.user_agent:=COALESCE(current_setting('mayi.user_agent',true),'');
 IF NEW.grant_id IS NOT NULL THEN
  SELECT CASE WHEN principal_type='user' THEN subject ELSE '' END,client_id,resource INTO NEW.user_id,NEW.client_id,NEW.resource FROM mayi.grants WHERE tenant_id=NEW.tenant_id AND grant_id=NEW.grant_id;
 END IF;
 IF NEW.user_id='' AND NEW.actor_id LIKE 'user:%' THEN NEW.user_id:=NEW.actor_id; END IF;
 IF NEW.client_id='' THEN
  SELECT w.client_id,w.resource_uri INTO NEW.client_id,NEW.resource FROM mayi.authorization_transactions w WHERE w.tenant_id=NEW.tenant_id AND (w.authorization_id=NEW.object_ref OR w.handle_hash=NEW.object_ref) LIMIT 1;
  IF NOT FOUND THEN
   SELECT p.client_id,p.resource_uri INTO NEW.client_id,NEW.resource FROM mayi.pushed_requests p WHERE p.tenant_id=NEW.tenant_id AND p.request_id=NEW.object_ref LIMIT 1;
  END IF;
 END IF;
 IF NEW.client_id IS NULL OR NEW.client_id='' THEN
  SELECT client_id INTO NEW.client_id FROM mayi.clients WHERE tenant_id=NEW.tenant_id AND client_id=NEW.object_ref;
 END IF;
 IF NEW.resource IS NULL OR NEW.resource='' THEN
  SELECT uri INTO NEW.resource FROM mayi.resources WHERE tenant_id=NEW.tenant_id AND resource_id=NEW.object_ref;
 END IF;
 NEW.client_id:=COALESCE(NEW.client_id,'');NEW.resource:=COALESCE(NEW.resource,'');NEW.user_id:=COALESCE(NEW.user_id,'');
 RETURN NEW;
END$$;
CREATE TRIGGER audit_context BEFORE INSERT ON mayi.audit_events FOR EACH ROW EXECUTE FUNCTION mayi.audit_request_context();
REVOKE ALL ON FUNCTION mayi.audit_request_context() FROM PUBLIC;
CREATE TABLE mayi.grant_usage(tenant_id text NOT NULL,grant_id text NOT NULL,last_checked_at timestamptz NOT NULL,token_checks bigint NOT NULL CHECK(token_checks>0),PRIMARY KEY(tenant_id,grant_id),FOREIGN KEY(tenant_id,grant_id) REFERENCES mayi.grants);
ALTER TABLE mayi.grant_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.grant_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.grant_usage USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
`
