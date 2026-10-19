package migrations

// ObjectCeilings preserves typed authority without inferring missing authority.
// Public RAR/PAR and object-bound issuance remain disabled during this stage.
const ObjectCeilings = `
CREATE FUNCTION mayi.valid_object_ceiling(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN value IS NULL THEN true ELSE COALESCE(
 jsonb_typeof(value)='object'
 AND value - ARRAY['version','semantics','resource','details'] = '{}'::jsonb
 AND value->'version'='1'::jsonb
 AND value->>'semantics'='object-actions-v1'
 AND jsonb_typeof(value->'resource')='string' AND length(value->>'resource') BETWEEN 1 AND 2048
 AND CASE WHEN jsonb_typeof(value->'details')='array' THEN jsonb_array_length(value->'details') BETWEEN 1 AND 32 ELSE false END
 AND octet_length(value::text)<=1048576, false) END
$$;
ALTER TABLE mayi.authorization_transactions ADD COLUMN object_ceiling jsonb CHECK(mayi.valid_object_ceiling(object_ceiling));
ALTER TABLE mayi.authorization_transactions ADD CHECK(object_ceiling IS NULL OR object_ceiling->>'resource'=resource_uri);
ALTER TABLE mayi.grants ADD COLUMN current_object_ceiling jsonb CHECK(mayi.valid_object_ceiling(current_object_ceiling));
ALTER TABLE mayi.grants ADD CHECK(current_object_ceiling IS NULL OR current_object_ceiling->>'resource'=resource);
ALTER TABLE mayi.grant_revisions ADD COLUMN object_ceiling jsonb CHECK(mayi.valid_object_ceiling(object_ceiling));
ALTER TABLE mayi.credentials ADD COLUMN object_ceiling jsonb CHECK(mayi.valid_object_ceiling(object_ceiling));
ALTER TABLE mayi.credentials ADD CHECK(object_ceiling IS NULL OR object_ceiling->>'resource'=resource);
ALTER TABLE mayi.refresh_families ADD COLUMN object_ceiling jsonb CHECK(mayi.valid_object_ceiling(object_ceiling));
ALTER TABLE mayi.issuances ADD COLUMN object_ceiling jsonb CHECK(mayi.valid_object_ceiling(object_ceiling));
ALTER TABLE mayi.issuances ADD CHECK(object_ceiling IS NULL OR object_ceiling->>'resource'=resource);

CREATE FUNCTION mayi.reject_object_ceiling_change() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN RAISE EXCEPTION 'object authority snapshot is immutable'; END$$;
CREATE TRIGGER immutable_authorization_objects BEFORE UPDATE OF object_ceiling ON mayi.authorization_transactions
 FOR EACH ROW WHEN (NEW.object_ceiling IS DISTINCT FROM OLD.object_ceiling) EXECUTE FUNCTION mayi.reject_object_ceiling_change();
-- No current-authority mutation use case exists yet. Freeze it rather than
-- admitting unchecked widening; revocation remains available. Later narrowing
-- needs its own domain decision and coordinated atomic predicates.
CREATE TRIGGER immutable_grant_objects BEFORE UPDATE OF current_object_ceiling ON mayi.grants
 FOR EACH ROW WHEN (NEW.current_object_ceiling IS DISTINCT FROM OLD.current_object_ceiling) EXECUTE FUNCTION mayi.reject_object_ceiling_change();
CREATE TRIGGER immutable_credential_objects BEFORE UPDATE OF object_ceiling ON mayi.credentials
 FOR EACH ROW WHEN (NEW.object_ceiling IS DISTINCT FROM OLD.object_ceiling) EXECUTE FUNCTION mayi.reject_object_ceiling_change();
CREATE TRIGGER immutable_family_objects BEFORE UPDATE OF object_ceiling ON mayi.refresh_families
 FOR EACH ROW WHEN (NEW.object_ceiling IS DISTINCT FROM OLD.object_ceiling) EXECUTE FUNCTION mayi.reject_object_ceiling_change();
CREATE TRIGGER immutable_issuance_objects BEFORE UPDATE OF object_ceiling ON mayi.issuances
 FOR EACH ROW WHEN (NEW.object_ceiling IS DISTINCT FROM OLD.object_ceiling) EXECUTE FUNCTION mayi.reject_object_ceiling_change();

-- Reinforce presence and audience binding, not a second permission comparator.
-- Subset decisions remain in the domain/service. Roots without object authority cannot silently
-- become object grants, and object descendants cannot drop the snapshot.
CREATE FUNCTION mayi.guard_object_lineage() RETURNS trigger LANGUAGE plpgsql AS
$$DECLARE ceiling jsonb; audience text;
BEGIN
 IF TG_OP='UPDATE' AND ROW(NEW.tenant_id,NEW.grant_id,NEW.revision) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.grant_id,OLD.revision)
 THEN RAISE EXCEPTION 'credential authority lineage is immutable'; END IF;
 IF TG_TABLE_NAME='grant_revisions' THEN
  SELECT current_object_ceiling,resource INTO ceiling,audience FROM mayi.grants
   WHERE tenant_id=NEW.tenant_id AND grant_id=NEW.grant_id;
 ELSE
  SELECT r.object_ceiling,g.resource INTO ceiling,audience FROM mayi.grant_revisions r JOIN mayi.grants g USING(tenant_id,grant_id)
   WHERE r.tenant_id=NEW.tenant_id AND r.grant_id=NEW.grant_id AND r.revision=NEW.revision;
 END IF;
 IF NOT FOUND OR (NEW.object_ceiling IS NULL)<>(ceiling IS NULL)
 OR (NEW.object_ceiling IS NOT NULL AND NEW.object_ceiling->>'resource' IS DISTINCT FROM audience)
 THEN RAISE EXCEPTION 'object authority lineage mismatch'; END IF;
 RETURN NEW;
END$$;
CREATE TRIGGER revision_object_lineage BEFORE INSERT OR UPDATE OF tenant_id,grant_id,revision,object_ceiling ON mayi.grant_revisions FOR EACH ROW EXECUTE FUNCTION mayi.guard_object_lineage();
CREATE TRIGGER credential_object_lineage BEFORE INSERT OR UPDATE OF tenant_id,grant_id,revision,object_ceiling ON mayi.credentials FOR EACH ROW EXECUTE FUNCTION mayi.guard_object_lineage();
CREATE TRIGGER family_object_lineage BEFORE INSERT OR UPDATE OF tenant_id,grant_id,revision,object_ceiling ON mayi.refresh_families FOR EACH ROW EXECUTE FUNCTION mayi.guard_object_lineage();
CREATE TRIGGER issuance_object_lineage BEFORE INSERT OR UPDATE OF tenant_id,grant_id,revision,object_ceiling ON mayi.issuances FOR EACH ROW EXECUTE FUNCTION mayi.guard_object_lineage();
REVOKE ALL ON FUNCTION mayi.valid_object_ceiling(jsonb),mayi.reject_object_ceiling_change(),mayi.guard_object_lineage() FROM PUBLIC;
`
