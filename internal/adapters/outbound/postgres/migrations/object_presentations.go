package migrations

// ObjectPresentations retains the first exact guarded consent display. It is
// approval evidence, not an authoritative copy of the resource owner's ACL.
const ObjectPresentations = `
CREATE FUNCTION mayi.valid_consent_labels(labels jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS
$$DECLARE entry jsonb;
BEGIN
 IF jsonb_typeof(labels) IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF jsonb_array_length(labels) NOT BETWEEN 1 AND 32 OR octet_length(labels::text)>131072 THEN RETURN false; END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(labels) LOOP
  IF jsonb_typeof(entry) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(entry))<>3 OR
   jsonb_typeof(entry->'type') IS DISTINCT FROM 'string' OR
   jsonb_typeof(entry->'identifier') IS DISTINCT FROM 'string' OR
   jsonb_typeof(entry->'name') IS DISTINCT FROM 'string' OR
   octet_length(entry->>'name') NOT BETWEEN 1 AND 256 OR (entry->>'name') ~ '[[:cntrl:]]'
   THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END$$;
CREATE TABLE mayi.authorization_object_presentations (
 tenant_id text NOT NULL, handle_hash text NOT NULL,
 session_hash text NOT NULL, subject text NOT NULL,
 client_id text NOT NULL, resource_uri text NOT NULL,
 permission_version bigint NOT NULL CHECK(permission_version>0),
 object_ceiling jsonb NOT NULL CHECK(mayi.valid_object_ceiling(object_ceiling) AND object_ceiling->>'resource'=resource_uri),
 objects jsonb NOT NULL CHECK(mayi.valid_consent_labels(objects)), presented_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,handle_hash),
 FOREIGN KEY(tenant_id,handle_hash) REFERENCES mayi.authorization_transactions(tenant_id,handle_hash),
 FOREIGN KEY(tenant_id,session_hash) REFERENCES mayi.browser_sessions(tenant_id,session_hash)
);
ALTER TABLE mayi.authorization_object_presentations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mayi.authorization_object_presentations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON mayi.authorization_object_presentations
 USING(tenant_id=current_setting('mayi.tenant_id',true)) WITH CHECK(tenant_id=current_setting('mayi.tenant_id',true));

CREATE FUNCTION mayi.guard_object_presentation() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'object presentation evidence is immutable'; END IF;
 PERFORM 1 FROM mayi.authorization_transactions w JOIN mayi.browser_sessions s
 ON s.tenant_id=w.tenant_id AND s.session_hash=w.consent_session_hash
 WHERE w.tenant_id=NEW.tenant_id AND w.handle_hash=NEW.handle_hash AND w.status='pending'
 AND w.pushed_request_hash IS NOT NULL AND w.consent_session_hash=NEW.session_hash AND s.subject=NEW.subject
 AND w.client_id=NEW.client_id AND w.resource_uri=NEW.resource_uri AND w.object_ceiling=NEW.object_ceiling
 AND NEW.presented_at>=w.created_at AND NEW.presented_at<w.expires_at
 AND jsonb_array_length(NEW.objects)=jsonb_array_length(NEW.object_ceiling->'details')
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.object_ceiling->'details') d
  WHERE (SELECT count(*) FROM jsonb_array_elements(NEW.objects) o WHERE o->>'type'=d->>'type' AND o->>'identifier'=d->>'identifier')<>1);
 IF NOT FOUND THEN RAISE EXCEPTION 'object presentation must match bound pushed workflow'; END IF;
 RETURN NEW;
END$$;
CREATE TRIGGER object_presentation_guard BEFORE INSERT OR UPDATE OR DELETE ON mayi.authorization_object_presentations
 FOR EACH ROW EXECUTE FUNCTION mayi.guard_object_presentation();

CREATE FUNCTION mayi.require_object_presentation() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN
 IF NEW.status='approved' AND NEW.pushed_request_hash IS NOT NULL THEN
  PERFORM 1 FROM mayi.authorization_object_presentations p
  WHERE p.tenant_id=NEW.tenant_id AND p.handle_hash=NEW.handle_hash AND p.session_hash=NEW.consent_session_hash
  AND p.subject=NEW.subject AND p.client_id=NEW.client_id AND p.resource_uri=NEW.resource_uri
  AND p.object_ceiling=NEW.object_ceiling AND p.presented_at<=NEW.decided_at;
  IF NOT FOUND THEN RAISE EXCEPTION 'object approval requires exact durable presentation'; END IF;
 END IF;
 RETURN NEW;
END$$;
CREATE TRIGGER require_object_presentation BEFORE INSERT OR UPDATE ON mayi.authorization_transactions
 FOR EACH ROW EXECUTE FUNCTION mayi.require_object_presentation();
REVOKE ALL ON FUNCTION mayi.valid_consent_labels(jsonb),mayi.guard_object_presentation(),mayi.require_object_presentation() FROM PUBLIC;
`
