package migrations

// Pushed stores one-use, typed request references without enabling a route.
const Pushed = `
CREATE TABLE mayi.pushed_requests (
 tenant_id text NOT NULL REFERENCES mayi.tenants, reference_hash text NOT NULL CHECK(reference_hash ~ '^[0-9a-f]{64}$'),
 request_id text NOT NULL, client_id text NOT NULL, redirect_uri text NOT NULL, resource_uri text NOT NULL,
 permission_scopes text[] NOT NULL, pkce_challenge text NOT NULL, binding_thumbprint text NOT NULL, client_state text NOT NULL CHECK(octet_length(client_state) BETWEEN 16 AND 1024),
 object_ceiling jsonb NOT NULL CHECK(mayi.valid_object_ceiling(object_ceiling) AND object_ceiling->>'resource'=resource_uri),
 policy_version bigint NOT NULL CHECK(policy_version>0), created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 consumed_at timestamptz, authorization_hash text,
 PRIMARY KEY(tenant_id,reference_hash), UNIQUE(tenant_id,request_id), UNIQUE(tenant_id,authorization_hash),
 FOREIGN KEY(tenant_id,client_id) REFERENCES mayi.clients,
 FOREIGN KEY(tenant_id,authorization_hash) REFERENCES mayi.authorization_transactions(tenant_id,handle_hash),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '90 seconds'),
 CHECK((consumed_at IS NULL AND authorization_hash IS NULL) OR
 (consumed_at IS NOT NULL AND authorization_hash IS NOT NULL AND authorization_hash<>reference_hash AND consumed_at>=created_at AND consumed_at<expires_at))
);
ALTER TABLE mayi.pushed_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.pushed_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.pushed_requests
 USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));
ALTER TABLE mayi.authorization_transactions ADD COLUMN pushed_request_hash text CHECK(pushed_request_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE mayi.authorization_transactions ADD UNIQUE(tenant_id,pushed_request_hash);
ALTER TABLE mayi.authorization_transactions ADD FOREIGN KEY(tenant_id,pushed_request_hash) REFERENCES mayi.pushed_requests(tenant_id,reference_hash);
ALTER TABLE mayi.authorization_transactions ADD CHECK(pushed_request_hash IS NULL OR object_ceiling IS NOT NULL);

CREATE FUNCTION mayi.guard_pushed_transition() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'pushed request history is immutable'; END IF;
 IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL OR NEW.authorization_hash IS NULL OR
 ROW(NEW.tenant_id,NEW.reference_hash,NEW.request_id,NEW.client_id,NEW.redirect_uri,NEW.resource_uri,NEW.permission_scopes,NEW.pkce_challenge,NEW.binding_thumbprint,NEW.client_state,NEW.object_ceiling,NEW.policy_version,NEW.created_at,NEW.expires_at)
 IS DISTINCT FROM
 ROW(OLD.tenant_id,OLD.reference_hash,OLD.request_id,OLD.client_id,OLD.redirect_uri,OLD.resource_uri,OLD.permission_scopes,OLD.pkce_challenge,OLD.binding_thumbprint,OLD.client_state,OLD.object_ceiling,OLD.policy_version,OLD.created_at,OLD.expires_at)
 THEN RAISE EXCEPTION 'pushed requests only permit one consumption transition'; END IF;
 RETURN NEW;
END$$;
CREATE TRIGGER pushed_transition BEFORE UPDATE OR DELETE ON mayi.pushed_requests FOR EACH ROW EXECUTE FUNCTION mayi.guard_pushed_transition();
CREATE FUNCTION mayi.reject_pushed_provenance_change() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN RAISE EXCEPTION 'pushed request provenance is immutable'; END$$;
CREATE TRIGGER immutable_pushed_provenance BEFORE UPDATE OF pushed_request_hash ON mayi.authorization_transactions
 FOR EACH ROW WHEN(NEW.pushed_request_hash IS DISTINCT FROM OLD.pushed_request_hash) EXECUTE FUNCTION mayi.reject_pushed_provenance_change();

-- Deferred consistency permits the service to insert the workflow and consume
-- its reference in one transaction; neither half may commit alone or be swapped.
CREATE FUNCTION mayi.check_pushed_link() RETURNS trigger LANGUAGE plpgsql AS
$$DECLARE ref text;
BEGIN
 IF TG_TABLE_NAME='pushed_requests' THEN
  IF NEW.authorization_hash IS NULL THEN RETURN NEW; END IF;
  ref:=NEW.reference_hash;
 ELSE
  IF NEW.pushed_request_hash IS NULL THEN RETURN NEW; END IF;
  ref:=NEW.pushed_request_hash;
 END IF;
 PERFORM 1 FROM mayi.pushed_requests p JOIN mayi.authorization_transactions w
 ON w.tenant_id=p.tenant_id AND w.handle_hash=p.authorization_hash AND w.pushed_request_hash=p.reference_hash
 WHERE p.tenant_id=NEW.tenant_id AND p.reference_hash=ref AND p.consumed_at=w.created_at
 AND ROW(p.client_id,p.redirect_uri,p.resource_uri,p.permission_scopes,p.pkce_challenge,p.binding_thumbprint,p.client_state,p.object_ceiling,p.policy_version)
 IS NOT DISTINCT FROM ROW(w.client_id,w.redirect_uri,w.resource_uri,w.permission_scopes,w.pkce_challenge,w.binding_thumbprint,w.client_state,w.object_ceiling,w.policy_version);
 IF NOT FOUND THEN RAISE EXCEPTION 'pushed request and workflow must commit together with the same snapshot'; END IF;
 RETURN NEW;
END$$;
CREATE CONSTRAINT TRIGGER pushed_link AFTER INSERT OR UPDATE ON mayi.pushed_requests DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION mayi.check_pushed_link();
CREATE CONSTRAINT TRIGGER workflow_pushed_link AFTER INSERT OR UPDATE ON mayi.authorization_transactions DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION mayi.check_pushed_link();
REVOKE ALL ON FUNCTION mayi.guard_pushed_transition(),mayi.reject_pushed_provenance_change(),mayi.check_pushed_link() FROM PUBLIC;
`
