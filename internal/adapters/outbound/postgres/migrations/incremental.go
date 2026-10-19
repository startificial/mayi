package migrations

// Incremental keeps a durable root while appending immutable consent revisions.
// Its restricted function is the only runtime authority-update capability.
const Incremental = `
ALTER TABLE mayi.authorization_transactions ADD COLUMN grant_revision bigint NOT NULL DEFAULT 1 CHECK(grant_revision>0);
CREATE FUNCTION mayi.guard_workflow_revision() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF OLD.status<>'pending' OR NEW.status<>'approved' THEN RAISE EXCEPTION 'revision changes require approval'; END IF; RETURN NEW;
END$$;
CREATE TRIGGER workflow_revision_guard BEFORE UPDATE OF grant_revision ON mayi.authorization_transactions FOR EACH ROW WHEN(NEW.grant_revision IS DISTINCT FROM OLD.grant_revision) EXECUTE FUNCTION mayi.guard_workflow_revision();
REVOKE ALL ON FUNCTION mayi.guard_workflow_revision() FROM PUBLIC;
DROP TRIGGER immutable_grant_objects ON mayi.grants;
CREATE FUNCTION mayi.extend_grant_authority(tenant text,reference text,expected bigint,permissions text[],objects jsonb,deadline timestamptz,workflow text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF tenant IS DISTINCT FROM current_setting('mayi.tenant_id',true) THEN RAISE EXCEPTION 'tenant context required'; END IF;
 PERFORM 1 FROM mayi.grants g JOIN mayi.authorization_transactions w ON w.tenant_id=g.tenant_id
 WHERE g.tenant_id=tenant AND g.grant_id=reference AND NOT g.revoked AND g.principal_type='user' AND g.expires_at>clock_timestamp()
 AND w.handle_hash=workflow AND w.status='pending' AND w.client_id=g.client_id AND w.resource_uri=g.resource
 AND w.consent_session_hash IS NOT NULL AND EXISTS(SELECT 1 FROM mayi.browser_sessions s WHERE s.tenant_id=tenant AND s.session_hash=w.consent_session_hash AND s.subject=g.subject AND NOT s.revoked AND s.expires_at>clock_timestamp())
 AND (SELECT max(revision) FROM mayi.grant_revisions WHERE tenant_id=tenant AND grant_id=reference)=expected
 FOR UPDATE OF g;
 IF NOT FOUND THEN RAISE EXCEPTION 'current grant approval conflict'; END IF;
 UPDATE mayi.grants SET current_scopes=permissions,current_object_ceiling=objects,expires_at=deadline WHERE tenant_id=tenant AND grant_id=reference;
END$$;
REVOKE ALL ON FUNCTION mayi.extend_grant_authority(text,text,bigint,text[],jsonb,timestamptz,text) FROM PUBLIC;
CREATE FUNCTION mayi.check_incremental_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM 1 FROM mayi.grant_revisions r JOIN mayi.authorization_transactions w ON w.tenant_id=r.tenant_id AND w.grant_id=r.grant_id AND w.grant_revision=r.revision
 WHERE r.tenant_id=NEW.tenant_id AND r.grant_id=NEW.grant_id AND r.scopes=NEW.current_scopes AND r.object_ceiling=NEW.current_object_ceiling AND r.expires_at=NEW.expires_at
 AND w.status='approved' AND w.subject=NEW.subject AND w.client_id=NEW.client_id AND w.resource_uri=NEW.resource;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant extension requires atomic consent revision'; END IF;
 RETURN NEW;
END$$;
CREATE CONSTRAINT TRIGGER incremental_approval AFTER UPDATE ON mayi.grants DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW WHEN(ROW(NEW.current_scopes,NEW.current_object_ceiling,NEW.expires_at) IS DISTINCT FROM ROW(OLD.current_scopes,OLD.current_object_ceiling,OLD.expires_at)) EXECUTE FUNCTION mayi.check_incremental_approval();
REVOKE ALL ON FUNCTION mayi.check_incremental_approval() FROM PUBLIC;
`
