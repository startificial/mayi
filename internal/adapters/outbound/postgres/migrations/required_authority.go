package migrations

// RequiredAuthority completes the fresh-deployment RAR/PAR contract. Existing
// preview rows without authority cause migration failure; no authority is inferred.
const RequiredAuthority = `
ALTER TABLE mayi.authorization_transactions ALTER COLUMN object_ceiling SET NOT NULL;
ALTER TABLE mayi.authorization_transactions ALTER COLUMN pushed_request_hash SET NOT NULL;
ALTER TABLE mayi.grants ALTER COLUMN current_object_ceiling SET NOT NULL;
ALTER TABLE mayi.grant_revisions ALTER COLUMN object_ceiling SET NOT NULL;
ALTER TABLE mayi.credentials ALTER COLUMN object_ceiling SET NOT NULL;
ALTER TABLE mayi.refresh_families ALTER COLUMN object_ceiling SET NOT NULL;
ALTER TABLE mayi.issuances ALTER COLUMN object_ceiling SET NOT NULL;
ALTER TABLE mayi.issuances ALTER COLUMN token_hash SET NOT NULL;
ALTER TABLE mayi.issuances ADD CHECK(token_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE mayi.credentials ALTER CONSTRAINT credentials_tenant_id_authorization_hash_fkey DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE mayi.credentials ADD CONSTRAINT interactive_code_requires_authorization CHECK(kind<>'authorization_code' OR authorization_hash IS NOT NULL);

-- Options are part of the immutable request. Missing rows and cross-request
-- OIDC/offline-access swaps must fail at commit, just like the RAR snapshot.
CREATE FUNCTION mayi.check_authorization_options() RETURNS trigger LANGUAGE plpgsql AS
$$DECLARE tenant text; reference text; handle text;
BEGIN
 tenant:=NEW.tenant_id;
 IF TG_TABLE_NAME IN ('pushed_requests','pushed_options') THEN
  reference:=NEW.reference_hash;
  SELECT authorization_hash INTO handle FROM mayi.pushed_requests WHERE tenant_id=tenant AND reference_hash=reference;
 ELSE
  handle:=NEW.handle_hash;
  SELECT pushed_request_hash INTO reference FROM mayi.authorization_transactions WHERE tenant_id=tenant AND handle_hash=handle;
 END IF;
 PERFORM 1 FROM mayi.pushed_options WHERE tenant_id=tenant AND reference_hash=reference;
 IF NOT FOUND THEN RAISE EXCEPTION 'pushed request options are required'; END IF;
 IF handle IS NOT NULL THEN
  PERFORM 1 FROM mayi.authorization_options w JOIN mayi.pushed_options p ON p.tenant_id=w.tenant_id
   WHERE w.tenant_id=tenant AND w.handle_hash=handle AND p.reference_hash=reference
   AND ROW(w.oidc,w.nonce,w.offline_access) IS NOT DISTINCT FROM ROW(p.oidc,p.nonce,p.offline_access);
  IF NOT FOUND THEN RAISE EXCEPTION 'authorization options must match the pushed request'; END IF;
 END IF;
 RETURN NEW;
END$$;
CREATE CONSTRAINT TRIGGER required_pushed_options AFTER INSERT OR UPDATE ON mayi.pushed_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mayi.check_authorization_options();
CREATE CONSTRAINT TRIGGER required_workflow_options AFTER INSERT OR UPDATE ON mayi.authorization_transactions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mayi.check_authorization_options();
CREATE CONSTRAINT TRIGGER linked_pushed_options AFTER INSERT ON mayi.pushed_options DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mayi.check_authorization_options();
CREATE CONSTRAINT TRIGGER linked_workflow_options AFTER INSERT ON mayi.authorization_options DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mayi.check_authorization_options();
REVOKE ALL ON FUNCTION mayi.check_authorization_options() FROM PUBLIC;
`
