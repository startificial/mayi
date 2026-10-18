package migrations

// Authorization adds the first P2 workflow boundary. Login/session creation is
// not exposed yet; membership and session records remain operator-only writes.
const Authorization = `
CREATE TABLE mayi.principal_memberships (
 tenant_id text NOT NULL REFERENCES mayi.tenants, subject text NOT NULL CHECK(subject LIKE 'user:%' AND length(subject)>5),
 active boolean NOT NULL DEFAULT true, PRIMARY KEY(tenant_id,subject)
);
CREATE TABLE mayi.browser_sessions (
 tenant_id text NOT NULL, session_hash text NOT NULL CHECK(session_hash ~ '^[0-9a-f]{64}$'), subject text NOT NULL,
 expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,session_hash), FOREIGN KEY(tenant_id,subject) REFERENCES mayi.principal_memberships
);
-- Identity writes conflict with the existing tenant coordination lock even
-- when performed by an operator rather than a future authentication adapter.
CREATE FUNCTION mayi.coordinate_identity_mutation() RETURNS trigger LANGUAGE plpgsql AS
$$DECLARE tenant text;
BEGIN
 IF TG_OP='DELETE' THEN tenant:=OLD.tenant_id; ELSE tenant:=NEW.tenant_id; END IF;
 IF TG_OP='UPDATE' AND (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.subject IS DISTINCT FROM NEW.subject)
 THEN RAISE EXCEPTION 'identity references are immutable'; END IF;
 PERFORM 1 FROM mayi.tenants WHERE tenant_id=tenant FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'identity mutation requires tenant context'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END$$;
CREATE TRIGGER coordinate_membership BEFORE INSERT OR UPDATE OR DELETE ON mayi.principal_memberships
 FOR EACH ROW EXECUTE FUNCTION mayi.coordinate_identity_mutation();
CREATE TRIGGER coordinate_session BEFORE INSERT OR UPDATE OR DELETE ON mayi.browser_sessions
 FOR EACH ROW EXECUTE FUNCTION mayi.coordinate_identity_mutation();
CREATE TABLE mayi.authorization_transactions (
 tenant_id text NOT NULL REFERENCES mayi.tenants, handle_hash text NOT NULL CHECK(handle_hash ~ '^[0-9a-f]{64}$'),
 authorization_id text NOT NULL, browser_binding_hash text NOT NULL CHECK(browser_binding_hash ~ '^[0-9a-f]{64}$'),
 csrf_hash text NOT NULL CHECK(csrf_hash ~ '^[0-9a-f]{64}$'), client_id text NOT NULL,
 redirect_uri text NOT NULL, resource_uri text NOT NULL, permission_scopes text[] NOT NULL,
 pkce_challenge text NOT NULL, binding_thumbprint text NOT NULL, client_state text NOT NULL,
 policy_version bigint NOT NULL CHECK(policy_version>0), created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 status text NOT NULL CHECK(status IN ('pending','approved','denied')),
 subject text, grant_id text, code_hash text, decided_at timestamptz, consent_session_hash text CHECK(consent_session_hash ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,handle_hash), UNIQUE(tenant_id,authorization_id),
 FOREIGN KEY(tenant_id,client_id) REFERENCES mayi.clients,
 FOREIGN KEY(tenant_id,grant_id) REFERENCES mayi.grants,
 FOREIGN KEY(tenant_id,code_hash) REFERENCES mayi.credentials(tenant_id,hash),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
 CHECK((status='pending' AND subject IS NULL AND grant_id IS NULL AND code_hash IS NULL AND decided_at IS NULL)
 OR (status='denied' AND consent_session_hash IS NOT NULL AND decided_at IS NOT NULL AND subject IS NULL AND grant_id IS NULL AND code_hash IS NULL AND decided_at>=created_at AND decided_at<expires_at)
 OR (status='approved' AND consent_session_hash IS NOT NULL AND decided_at IS NOT NULL AND subject IS NOT NULL AND subject LIKE 'user:%' AND grant_id IS NOT NULL AND code_hash IS NOT NULL AND decided_at>=created_at AND decided_at<expires_at))
);
ALTER TABLE mayi.credentials ADD COLUMN authorization_hash text;
ALTER TABLE mayi.credentials ADD FOREIGN KEY(tenant_id,authorization_hash) REFERENCES mayi.authorization_transactions(tenant_id,handle_hash);
CREATE FUNCTION mayi.guard_authorization_transition() RETURNS trigger LANGUAGE plpgsql AS
$$BEGIN
 IF OLD.status<>'pending' OR
 ROW(NEW.tenant_id,NEW.handle_hash,NEW.authorization_id,NEW.browser_binding_hash,NEW.csrf_hash,NEW.client_id,NEW.redirect_uri,NEW.resource_uri,NEW.permission_scopes,NEW.pkce_challenge,NEW.binding_thumbprint,NEW.client_state,NEW.policy_version,NEW.created_at,NEW.expires_at)
 IS DISTINCT FROM
 ROW(OLD.tenant_id,OLD.handle_hash,OLD.authorization_id,OLD.browser_binding_hash,OLD.csrf_hash,OLD.client_id,OLD.redirect_uri,OLD.resource_uri,OLD.permission_scopes,OLD.pkce_challenge,OLD.binding_thumbprint,OLD.client_state,OLD.policy_version,OLD.created_at,OLD.expires_at)
 THEN RAISE EXCEPTION 'authorization request and final decision are immutable'; END IF;
 IF NEW.status='pending' THEN
  IF OLD.consent_session_hash IS NOT NULL OR NEW.consent_session_hash IS NULL OR
  ROW(NEW.subject,NEW.grant_id,NEW.code_hash,NEW.decided_at) IS DISTINCT FROM ROW(OLD.subject,OLD.grant_id,OLD.code_hash,OLD.decided_at)
  THEN RAISE EXCEPTION 'consent session binding is immutable'; END IF;
 ELSE
  IF NEW.status NOT IN ('approved','denied') OR OLD.consent_session_hash IS NULL OR NEW.consent_session_hash IS DISTINCT FROM OLD.consent_session_hash
  THEN RAISE EXCEPTION 'consent requires its bound session'; END IF;
 END IF;
 RETURN NEW;
END$$;
CREATE TRIGGER authorization_transition BEFORE UPDATE ON mayi.authorization_transactions
 FOR EACH ROW EXECUTE FUNCTION mayi.guard_authorization_transition();
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['principal_memberships','browser_sessions','authorization_transactions'] LOOP
  EXECUTE format('ALTER TABLE mayi.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE mayi.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_scope ON mayi.%I USING (tenant_id = current_setting(''mayi.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''mayi.tenant_id'', true))',name);
 END LOOP;
END $policies$;
REVOKE ALL ON FUNCTION mayi.guard_authorization_transition(),mayi.coordinate_identity_mutation() FROM PUBLIC;
`
